// backup_tool: benign program that restores N files by ABSOLUTE path.
// Legitimate, but it trips the same "many files fast" rule -> a false alarm.
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <cstdio>
#include <cstdlib>
#include <string>
int main(int argc, char** argv){
    if(argc<3){fprintf(stderr,"usage: %s <dir> <n>\n",argv[0]);return 1;}
    std::string dir=argv[1]; int n=atoi(argv[2]);
    if(dir.rfind("/tmp/ransom_test",0)!=0){fprintf(stderr,"refusing\n");return 1;}
    mkdir(dir.c_str(),0755);
    for(int i=0;i<n;i++){
        char p[256]; snprintf(p,sizeof p,"%s/restored_%03d.dat",dir.c_str(),i);
        int fd=open(p,O_WRONLY|O_CREAT,0644);          // absolute path
        if(fd<0)continue;
        std::string d(4096,'B'); write(fd,d.data(),d.size()); close(fd);
    }
    printf("backup restored %d files\n",n);
    return 0;
}
