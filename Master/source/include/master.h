#ifndef _MASTER_H
#define _MASTER_H

extern PWSTR MasterPipeName;

static
VOID
FORCEINLINE
InitMaster(
    IN PWSTR szName
    )
{
    MasterPipeName = szName;
}


BOOL
StartMaster(VOID);

#endif
