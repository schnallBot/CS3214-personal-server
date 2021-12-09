/**
 * Josh Ho (hojosh2000), Zachary Zawitoski (zachzaw); CS3214
 * p2 -- threadpool
 */


#include "threadpool.h"
#include "list.h"
#include <pthread.h>
#include <stdbool.h>
#include <semaphore.h>
#include <stdlib.h>


/* represents a thread pool */
struct thread_pool {
    struct list globalTasks;        // global queue of tasks
    struct list workers;            // list of all workers
    int nWorkers;                   // number of workers 
    bool time2die;                  // shutdown status
    pthread_mutex_t lock;           // lock for the pool
    pthread_cond_t wakeyWorkers;    // signal to wake workers for new task / shutting down
    pthread_barrier_t goSignal;     // for start synchronization
};


/* represents a future */
struct future {
    struct list_elem elem;
    fork_join_task_t task;          // future's task
    void* data;                     // task arguments
    void* result;                   // task result
    struct thread_pool* pool;       // threadpool the future belonds to
    sem_t doneSignal;               // signaled when future is done executing
    bool isStarted;                 // future started running yet?
};


/* represents a single worker */
struct worker {
    struct list_elem elem;
    pthread_t myThread;             // worker's thread
    struct list workerTasks;        // worker's own queue of tasks
};


/* thread-local info */
static __thread struct worker* localWorker;
static __thread bool isWorker;


/* used by thread function to check whether to keep sleeping or wakey */
static bool needs_sleep(struct thread_pool* pool) {
    // first, check all workers if their local queue is empty
    for (struct list_elem* e = list_begin(&pool->workers); e != list_end(&pool->workers); e = list_next(e)) {
        struct worker* currWorker = list_entry(e, struct worker, elem);
        if (!list_empty(&currWorker->workerTasks))  // if local queue contains something, worker needs to wake
            return false;
    }

    // all other cases -- sleep if pool is not shutting down and global queue is empty
    return !pool->time2die && list_empty(&pool->globalTasks);
}


/* looks for a task to steal */
static struct list_elem* steal_task(struct thread_pool* pool) {
    // check all workers for a task to steal
    for (struct list_elem* e = list_begin(&pool->workers); e != list_end(&pool->workers); e = list_next(e)) {
        struct worker* currWorker = list_entry(e, struct worker, elem);
        if (!list_empty(&currWorker->workerTasks))  // if local queue contains something, steal from back
            return list_pop_back(&currWorker->workerTasks);
    }

    // shouldn't get to this point!
    return NULL;
}


/* thread function */
static void* work_it(void* arg) {
    struct thread_pool* pool = (struct thread_pool*) arg;

    // wait until all threads are created before running
    pthread_barrier_wait(&pool->goSignal);

    pthread_mutex_lock(&pool->lock);
    
    // set local worker info
    for (struct list_elem* e = list_begin(&pool->workers); e != list_end(&pool->workers); e = list_next(e)) {
        struct worker* currWorker = list_entry(e, struct worker, elem);
        if (currWorker->myThread == pthread_self()) {
            localWorker = currWorker;
            break;
        }
    }
    isWorker = true;

    pthread_mutex_unlock(&pool->lock);

    //begin looping continuously
    while (true) {
        pthread_mutex_lock(&pool->lock);

        // sleep until woken up
        while (needs_sleep(pool))
            pthread_cond_wait(&pool->wakeyWorkers, &pool->lock);
        
        // if shutting down, exit
        if (pool->time2die) {
            pthread_mutex_unlock(&pool->lock);
            pthread_exit(NULL);
            return NULL;
        }

        // find a future to run
        struct list_elem* e;
        // case 1: if worker queue has something, grab it
        if (!list_empty(&localWorker->workerTasks))
            e = list_pop_front(&localWorker->workerTasks);
        // case 2: if global queue has something, grab it
        else if (!list_empty(&pool->globalTasks))
            e = list_pop_front(&pool->globalTasks);
        // case 3: otherwise, find one to steal
        else
            e = steal_task(pool);

        // convert to future to run
        struct future* toRun = list_entry(e, struct future, elem);
        toRun->isStarted = true;

        pthread_mutex_unlock(&pool->lock);

        // run future and notify future_get via semaphore
        toRun->result = (toRun->task)(pool, toRun->data);
        sem_post(&toRun->doneSignal);
    }

    return NULL;
}


/* creates a new thread pool with <nthreads> threads */
struct thread_pool * thread_pool_new(int nthreads) {
    // initialize pool, lock and signals
    struct thread_pool* newPool = malloc(sizeof(struct thread_pool));
    pthread_mutex_init(&newPool->lock, NULL);
    pthread_cond_init(&newPool->wakeyWorkers, NULL);
    pthread_barrier_init(&newPool->goSignal, NULL, nthreads);  // <nthreads> must be created before it can go

    // init everything else
    list_init(&newPool->globalTasks);
    list_init(&newPool->workers);
    newPool->nWorkers = nthreads;
    newPool->time2die = false;

    // this thread isn't a worker
    isWorker = false;

    pthread_mutex_lock(&newPool->lock);

    // create nthreads worker threads
    for (int i = 0; i < nthreads; i++) {
        struct worker* newWorker = malloc(sizeof(struct worker));
        list_push_front(&newPool->workers, &newWorker->elem);
        list_init(&newWorker->workerTasks);
        pthread_create(&newWorker->myThread, NULL, work_it, newPool);
    }

    pthread_mutex_unlock(&newPool->lock);

    return newPool;
}


/* shuts down the thread pool and frees/destroys everything */
void thread_pool_shutdown_and_destroy(struct thread_pool * pool) {
    pthread_mutex_lock(&pool->lock);

    // alert workers to shut down
    pool->time2die = true;
    pthread_cond_broadcast(&pool->wakeyWorkers);

    pthread_mutex_unlock(&pool->lock);

    // for each worker, join its thread then free it
    while (!list_empty(&pool->workers)) {
        struct list_elem* e = list_pop_front(&pool->workers);
        struct worker* currWorker = list_entry(e, struct worker, elem);
        pthread_join(currWorker->myThread, NULL);
        free(currWorker);
    }

    // destroy stuff and free pool
    pthread_mutex_destroy(&pool->lock);
    pthread_cond_destroy(&pool->wakeyWorkers);
    pthread_barrier_destroy(&pool->goSignal);
    free(pool);
}


/* submits a new task to the pool */
struct future * thread_pool_submit(struct thread_pool *pool, fork_join_task_t task, void * data) {
    // init new future and populate fields
    struct future* newFuture = malloc(sizeof(struct future));
    sem_init(&newFuture->doneSignal, 0, 0);
    newFuture->task = task;
    newFuture->data = data;
    newFuture->pool = pool;
    newFuture->isStarted = false;

    pthread_mutex_lock(&pool->lock);

    // if called in local worker, add to worker queue
    // otherwise, add to global queue
    if (isWorker)
        list_push_front(&localWorker->workerTasks, &newFuture->elem);
    else
        list_push_back(&pool->globalTasks, &newFuture->elem);

    // wake up workers
    pthread_cond_signal(&pool->wakeyWorkers);
    
    pthread_mutex_unlock(&pool->lock);

    return newFuture;
}


/* gets the result of a future */
void * future_get(struct future * fut) {
    pthread_mutex_lock(&fut->pool->lock);

    // if future hasn't started running, main thread execs it
    // otherwise, wait for it
    if (!fut->isStarted) {
        list_remove(&fut->elem);
        fut->isStarted = true;

        pthread_mutex_unlock(&fut->pool->lock);

        fut->result = (fut->task)(fut->pool, fut->data);
    }
    else {
        pthread_mutex_unlock(&fut->pool->lock);

        sem_wait(&fut->doneSignal);
    }

    return fut->result;
}


/* frees a future */
void future_free(struct future * fut) {
    // destroy semaphore and free future
    sem_destroy(&fut->doneSignal);
    free(fut);
}