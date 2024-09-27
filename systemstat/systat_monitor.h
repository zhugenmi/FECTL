#include <stdio.h>
#include <time.h>

#define DEVICE_NAME "/dev/systat"

struct MEM_STATE{ 
        int total; 
        int free;
        int mem_utilization;
};

struct CPU_STATE{ 
        long long user;         //用户态执行时间
        long long nice;         //低优先级任务执行时间
        long long system;       //内核态执行时间
        long long idle;         //空闲时间 
        int       num_cores;

};

struct loc_time{
        int     hour;
        int     min;
        int     sec;
};

struct SYSTAT{
        struct loc_time time;
        int mem_utilization;
        int cpu_utilization;
        float load_avg;
};

struct MEM_STATE get_mem_info() {
        struct MEM_STATE info;
        FILE *fp; 
        char tmp[15]; 
        fp = fopen("/proc/meminfo","r"); 
        fscanf(fp,"%s",tmp); 
        fscanf(fp,"%d",&(info.total));
        fscanf(fp,"%s",tmp);
        fscanf(fp,"%s",tmp); 
        fscanf(fp,"%d",&(info.free));
        fclose(fp); 
        info.mem_utilization=100-info.free*1.0/info.total*100;
        // printf("info.free: %d, info.total: %d, info.utilization: %d \n",info.free,info.total,info.mem_utilization);
        return info;
}

struct CPU_STATE get_cpu_state() {
        char tmp[5]; 
        struct CPU_STATE info; 
        FILE *fp; fp = fopen("/proc/stat","r"); //fseek(fp,1); fscanf(fp,"%s",tmp);
        /*根据文件内容读取时间片信息*/
        fscanf(fp,"%lld%lld%lld%lld",&(info.user), &(info.nice),&(info.system),&(info.idle));
        fclose(fp); 
        info.num_cores=4;
        return info;
}

struct loc_time get_current_time(){
        struct loc_time loc_time;
        time_t tmp;
        struct tm *p;
        time(&tmp);
        p=localtime(&tmp);
        loc_time.hour=p->tm_hour;
        loc_time.min=p->tm_min;
        loc_time.sec=p->tm_sec;
        return loc_time;
}

//获取系统最近一分钟的平均负载值
float get_loadavg(){
        float loadavg_1min=0.0;
        FILE*fp;
        fp=fopen("/proc/loadavg","r");
        fscanf(fp,"%f",&loadavg_1min); 
        fclose(fp);
        return loadavg_1min;
}

int get_cpu_occupy(struct CPU_STATE* state1,struct CPU_STATE*state2){
        long long total1;
        long long total2;
        int cpu_usage;

        total1=state1->user+state1->nice+state1->system+state1->idle;
        total2=state2->user+state2->nice+state2->system+state2->idle;

        if(total2-total1!=0){
                cpu_usage=100-(state2->idle-state1->idle)*100.0/(total1+total2);

        }
        else{
                cpu_usage=0;
        }
        return cpu_usage;
} 

struct SYSTAT generate_systat()
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
        
        return systat;
}

int systat_write(struct SYSTAT systat)
{
    FILE *file;
    file=fopen(DEVICE_NAME,"w+");
    if(file!=NULL){
            fprintf(file,"%d %d %d %d %d %02f \n",
                    systat.time.hour,systat.time.min,systat.time.sec,
                    systat.mem_utilization,systat.cpu_utilization,
                    systat.load_avg);
            fclose(file);
            file=NULL;
    }
    else{
            printf("failed to open the file: %s.\n",DEVICE_NAME);
            return 0;
    }
    return 1;
}

struct SYSTAT systat_read()
{
    FILE *file;
    struct SYSTAT systat;
    file=fopen(DEVICE_NAME,"r");
    if(file!=NULL){
            fscanf(file,"%d %d %d %d %d %02f",
                    &systat.time.hour,&systat.time.min,&systat.time.sec,
                    &systat.mem_utilization,&systat.cpu_utilization,
                    &systat.load_avg);
            fclose(file);
            file=NULL;
    }
    else{
            printf("failed to open the file: %s.\n",DEVICE_NAME);
    }
    return systat;
}