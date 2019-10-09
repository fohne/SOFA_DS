#include <time.h>
#include <stdio.h>
int main()
{
/*
 *
 * struct timespec {
        time_t   tv_sec;        //seconds 
        long     tv_nsec;       // nanoseconds 
   };

    CLOCK_REALTIME
    CLOCK_MONOTONIC
    CLOCK_PROCESS_CPUTIME_ID
    CLOCK_THREAD_CPUTIME_ID 
 */
    struct timespec ts;

    //printf("Real,Mono,Process,Thread\n");
    printf("Real, Mono\n");
    for(int i = 0; i < 100; i++){
    clock_gettime(CLOCK_REALTIME, &ts);
    printf("%ld.%ld, ",ts.tv_sec, ts.tv_nsec);
    clock_gettime(CLOCK_MONOTONIC, &ts);
    printf("%ld.%ld\n",ts.tv_sec, ts.tv_nsec);}
/*
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
    printf("%ld.%ld,",ts.tv_sec, ts.tv_nsec);
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
    printf("%ld.%ld\n",ts.tv_sec, ts.tv_nsec);
*/
    return 0;
}
