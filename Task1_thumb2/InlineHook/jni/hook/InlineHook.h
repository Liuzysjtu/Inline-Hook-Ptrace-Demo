/***************************************************
 *  Author :yong夜
 *
 *  声明Inline Hook过程中用到的所有功能函数、头文件
 *  目前支持32位系统的arm32、thumb-2指令集
 * *************************************************/
#ifndef _INLINEHOOK_H
#define _INLINEHOOK_H

#include <stdio.h>
#include <Android/log.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <stdbool.h>

#ifndef BYTE
#define BYTE unsigned char
#endif

#define ARM32OPCODEMAXLEN 8     //32bit ARM指令集需要替换的指令长度
#define OPCODEMAXLEN 12      //inline hook所需要的opcodes最大长度,arm为8，thumb为12/10（因为要补一个nop），所以这里取12，当arm的时候只memcpy 8btye就行了
#define BACKUP_CODE_NUM_MAX 10  //尽管备份指令最多的可能是thumb-2下的6条thumb16，但是为了保险起见选择了10。

#define LOG_TAG "InlineHook"
#define LOGI(format, args...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, format, ##args)

#define PAGE_START(addr)	(~(PAGE_SIZE - 1) & (addr))
#define SET_BIT0(addr)		(addr | 1)
#define CLEAR_BIT0(addr)	(addr & 0xFFFFFFFE)
#define TEST_BIT0(addr)		(addr & 1)

#define ACTION_ENABLE	0
#define ACTION_DISABLE	1

/* arm shellcode里用到的参数、变量*/
extern unsigned long _shellcode_start_s;
extern unsigned long _shellcode_end_s;
extern unsigned long _hookstub_function_addr_s; //根函数地址
extern unsigned long _old_function_addr_s;  //原指令地址

/* thumb-2 shellcode里用到的参数和变量*/
extern unsigned long _shellcode_start_s_thumb;
extern unsigned long _shellcode_end_s_thumb;
extern unsigned long _hookstub_function_addr_s_thumb; //根函数地址
extern unsigned long _old_function_addr_s_thumb; 

/* hook点信息*/
typedef struct armHookPointInfo
{
    void *pHookAddr;                        //需要hook的位置
    void *pStubShellCodeAddr;               //桩函数(shellcode)地址
    void (*onCallBack)(struct pt_regs *);   //用户自定义的替换函数
    void **ppOldFuncAddr;                   //*ppOldFuncAddr即指向原指令函数处的指针
    BYTE szbyBackupOpcodes[ARM32OPCODEMAXLEN];   //原指令的opcode
} ARM_INLINE_HOOK_INFO;

typedef struct thumbHookPointInfo
{
    void *pHookAddr; 
    void *pStubShellCodeAddr;
    void (*onCallBack)(struct pt_regs *);
    void **ppOldFuncAddr;
    BYTE szbyBackupOpcodes[OPCODEMAXLEN];
    int backUpLength; //备份代码的长度，arm模式下为8，thumb模式下为10或12
    int backUpFixLengthList[BACKUP_CODE_NUM_MAX]; //保存
    uint32_t *pNewEntryForOldFunction;
} THUMB_INLINE_HOOK_INFO;

/* common function */
bool ChangePageProperty(void *pAddress, size_t size);

extern void * GetModuleBaseAddr(pid_t pid, char* pszModuleName);

/* For 32 bit Arm instruction set */
bool InitArmHookInfo(ARM_INLINE_HOOK_INFO* pstInlineHook);

bool BuildArmStub(ARM_INLINE_HOOK_INFO* pstInlineHook);

bool BuildArmJumpCode(void *pCurAddress , void *pJumpAddress);

bool BuildArmOldFunction(ARM_INLINE_HOOK_INFO* pstInlineHook);

bool RebuildArmHookTarget(ARM_INLINE_HOOK_INFO* pstInlineHook);

extern bool RestoreArmHookTarget(ARM_INLINE_HOOK_INFO* pstInlineHook);

extern bool HookArm(ARM_INLINE_HOOK_INFO* pstInlineHook);

/* For Thumb-2 instruction set */
bool InitThumbHookInfo(THUMB_INLINE_HOOK_INFO* pstInlineHook);

bool BuildThumbStub(THUMB_INLINE_HOOK_INFO* pstInlineHook);

bool BuildThumbJumpCode(void *pCurAddress , void *pJumpAddress);

bool BuildThumbOldFunction(THUMB_INLINE_HOOK_INFO* pstInlineHook);

bool RebuildThumbHookTarget(THUMB_INLINE_HOOK_INFO* pstInlineHook);

extern bool RestoreThumbHookTarget(THUMB_INLINE_HOOK_INFO* pstInlineHook);

extern bool HookThumb(THUMB_INLINE_HOOK_INFO* pstInlineHook);

#endif