#include <unistd.h>
#include "systat_monitor.h"

int main(int arc,char *argv[])
{
        int cpu_usage,ret;
        struct loc_time loc_time;
        struct MEM_STATE meminfo;
        struct CPU_STATE cpu_state1;
        struct CPU_STATE cpu_state2;
        struct SYSTAT systat;
        
        loc_time=get_current_time();
        meminfo=get_mem_info();
        cpu_state1=get_cpu_state();
        sleep(3);
        cpu_state2=get_cpu_state();
        cpu_usage=get_cpu_occupy(&(cpu_state1),&(cpu_state2));

        systat.time=loc_time;
        systat.mem_utilization=meminfo.mem_utilization;
        systat.cpu_utilization=cpu_usage;
        systat.load_avg=get_loadavg();

        // ret=systat_write(systat);
        // if(!ret){
        //         printf("failed to write. file: %s.\n",DEVICE_NAME);
        // }


        struct SYSTAT ss;
        ss=systat_read();
        printf("read from the file: \n");
        printf("time：%d:%02d:%02d\n",ss.time.hour,ss.time.min,ss.time.sec);
        printf("memory utilization: %d %% \n",ss.mem_utilization);
        printf("load average: %.02f\n",ss.load_avg);
        printf("cpu utilization: %d %%\n",ss.cpu_utilization);
        return 0;
}