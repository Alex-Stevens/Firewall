// **************************************************
// Read me
// **************************************************
// References
// **************************************************
// 
// **************************************************
// Notes
// **************************************************
// 
// **************************************************

#define _GNU_SOURCE
#define BUFFER_SIZE 1000

#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
    // **************************************************
    // Incorrect usage
    // **************************************************
    
    if(argc < 2)
    {
        printf("Usage:\n");
        printf(" %s L            to display rules in kern.log\n", argv[0]);
        printf(" %s W <filename> to load new rules\n", argv[0]);
        return 1;
    }

    // **************************************************
    // Write filter list to the kernel log
    // **************************************************
    
    if(strcmp(argv[1],"L") == 0)
    {
        FILE* fd = fopen("/proc/firewallExtension", "w");
        if(fd == 0)
        {
            perror("Unable to communicate with the firewall extension");
            return 1;
        }

        fprintf(fd, "L");
        fclose(fd);

        return 0;
    }

    // **************************************************
    // Process new filter list
    // **************************************************
    
    if(strcmp(argv[1],"W") == 0)
    {
        FILE* fd = fopen(argv[2], "r");
        if(fd == 0)
        {
            perror("Unable to open file containing filter list");
            return 1;
        }
        
        char buffer[BUFFER_SIZE];
        
        while(fgets(buffer, sizeof(buffer), fd))
        {     
            unsigned int portNumber;
            char program[100];
            
            if( 2 != sscanf(buffer, "%u %s", &portNumber, program) )
            {
                fprintf(stderr, "ERROR: Ill-formed file \n");
                return 1;
            }
            
            if(access(program, X_OK))
            {
                fprintf(stderr, "ERROR: Cannot execute file \n");
                return 1;
            }
        }
        
        fclose(fd);
        
        fd = fopen(argv[2], "r");
        if(fd == 0)
        {
            perror("Unable to open file containing filter list");
            return 1;
        }
        
        FILE* krnl = fopen("/proc/firewallExtension", "w");
        if(krnl == 0)
        {
            perror("Unable to communicate with the firewall extension");
            return 1;
        }
        
        while(fgets(buffer, sizeof(buffer), fd))
        {     
            unsigned int portNumber;
            char program[100];
            
            if( 2 != sscanf(buffer, "%u %s", &portNumber, program) )
            {
                fprintf(stderr, "ERROR: Ill-formed file \n");
                return 1;
            }
            
            if(access(program, X_OK))
            {
                fprintf(stderr, "ERROR: Cannot execute file \n");
                return 1;
            }
            
            printf("Port: %u Program: %s \n", portNumber, program);
            fprintf(krnl, "%u %s\n", portNumber, program);
        }
        
        fclose(fd);
        fclose(krnl);
        return 0;
    } 

    printf("Usage:\n ");
    printf("+L to display rules in kern.log\n");
    printf("+\n");
    printf("%s",argv[1]);

    return 1;
}
