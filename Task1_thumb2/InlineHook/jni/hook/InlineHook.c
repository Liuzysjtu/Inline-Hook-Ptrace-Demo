#include "InlineHook.h"
#include "fixOpcode.h"

#define ALIGN_PC(pc) (pc & 0xFFFFFFFC)

/**
 *  通用函数：获取so模块加载进内存的基地址，通过查看/proc/$pid/maps文件
 *  
 *  @param  pid             模块所在进程pid，如果访问自身进程，可填小余0的值，如-1
 *  @param  pszModuleName   模块名字
 *  @return void*           模块的基地址，错误返回0 
 */
void *GetModuleBaseAddr(pid_t pid, char *pszModuleName) {
    FILE *pFileMaps = NULL;
    unsigned long ulBaseValue = 0;
    char szMapFilePath[256] = {0};
    char szFileLineBuffer[1024] = {0};

    /* 判断是否为自身maps文件*/
    if (pid < 0) {
        snprintf(szMapFilePath, sizeof(szMapFilePath), "/proc/self/maps");
    } else {
        snprintf(szMapFilePath, sizeof(szMapFilePath), "/proc/%d/maps", pid);
    }

    pFileMaps = fopen(szMapFilePath, "r");
    if (NULL == pFileMaps) {
        return (void *) ulBaseValue;
    }
    /* 循环遍历maps文件，找到对应模块名，截取字符串中的基地址*/
    while (fgets(szFileLineBuffer, sizeof(szFileLineBuffer), pFileMaps) != NULL) {
        if (strstr(szFileLineBuffer, pszModuleName)) {
            char *pszModuleAddress = strtok(szFileLineBuffer, "-");
            ulBaseValue = strtoul(pszModuleAddress, NULL, 16);

            if (ulBaseValue == 0x8000) {
                ulBaseValue = 0;
            }
            break;
        }
    }
    fclose(pFileMaps);

    return (void *) ulBaseValue;
}

/**
 * 通用函数，修改页属性，让内存块内的代码可执行
 *
 * @param   pAddress    需要修改属性起始地址
 * @param   size        需要修改页属性的长度
 * @return  bool        是否修改成功
 */
bool ChangePageProperty(void *pAddress, size_t size) {
    bool bRet = false;

    while (1) {
        if (pAddress == NULL) {
            LOGI("change page property error.");
            break;
        }

        unsigned long ulPageSize = sysconf(_SC_PAGESIZE);
        int iProtect = PROT_READ | PROT_WRITE | PROT_EXEC;
        /*页对齐，以4096的倍数为起始位置*/
        unsigned long ulNewPageStartAddress = (unsigned long) (pAddress) & ~(ulPageSize - 1);
        /* 计算至少需要多少内存页(0x1000byte)可以包含size大小*/
        long lPageCount = (size / ulPageSize) + 1;
        int iRet = mprotect((const void *) (ulNewPageStartAddress), lPageCount * ulPageSize,
                            iProtect);

        if (iRet == -1) {
            LOGI("mprotect error:%s", strerror(errno));
            break;
        }

        bRet = true;
        break;
    }

    return bRet;
}

/**
 *  ARM32：初始化hook点信息，保存原指令的opcode
 *  
 *  @param  pstInlineHook   保存hook点信息的结构体
 *  @return bool            是否初始化成功
 */
bool InitArmHookInfo(ARM_INLINE_HOOK_INFO *pstInlineHook) {
    bool bRet = false;

    while (1) {
        if (pstInlineHook == NULL) {
            LOGI("arm pstInlineHook is null");
            break;
        }

        memcpy(pstInlineHook->szbyBackupOpcodes, pstInlineHook->pHookAddr, 8);
        bRet = true;
        break;
    }

    return bRet;
}

/**
 *  ARM32：构造桩函数
 *
 *  @param  pstInlineHook   保存hook点信息的结构体
 *  @return bool            是否构造成功
 */
bool BuildArmStub(ARM_INLINE_HOOK_INFO *pstInlineHook) {
    bool bRet = false;

    while (1) {
        if (pstInlineHook == NULL) {
            LOGI("arm pstInlineHook is null");
            break;
        }

        /* 需要在shellcode中定义的四个全局变量。*/
        void *p_shellcode_start_s = &_shellcode_start_s;
        void *p_shellcode_end_s = &_shellcode_end_s;
        void *p_hookstub_function_addr_s = &_hookstub_function_addr_s;
        void *p_old_function_addr_s = &_old_function_addr_s;
        /* 申请一块内存，放入桩函数的shellcode*/
        size_t sShellCodeLength = p_shellcode_end_s - p_shellcode_start_s;
        void *pNewShellCode = malloc(sShellCodeLength);

        if (pNewShellCode == NULL) {
            \
            LOGI("arm shellcode malloc fail.");
            break;
        }
        memcpy(pNewShellCode, p_shellcode_start_s, sShellCodeLength);
        if (ChangePageProperty(pNewShellCode, sShellCodeLength) == false) {
            LOGI("change shell code page property fail.");
            break;
        }

        /* ppHookStubFunctionAddr的值是一个变量值的地址。这个变量值是shellcode中用户自定义函数地址(在新申请的空间中)*/
        void **ppHookStubFunctionAddr =
                pNewShellCode + (p_hookstub_function_addr_s - p_shellcode_start_s);
        *ppHookStubFunctionAddr = pstInlineHook->onCallBack;
        /* 桩函数地址*/
        pstInlineHook->pStubShellCodeAddr = pNewShellCode;
        /* _old_function_addr_s变量的地址，这个变量值就是原指令函数的函数指针值*/
        pstInlineHook->ppOldFuncAddr =
                pNewShellCode + (p_old_function_addr_s - p_shellcode_start_s);

        bRet = true;
        break;
    }

    return bRet;
}

/**
 *  ARM32：构造跳转指令。
 *
 *  @param  pCurAddress      当前地址，要构造跳转指令的位置
 *  @param  pJumpAddress     目的地址，要从当前位置跳过去的地址
 *  @return bool             跳转指令是否构造成功
 */
bool BuildArmJumpCode(void *pCurAddress, void *pJumpAddress) {
    bool bRet = false;

    while (1) {
        if (pCurAddress == NULL || pJumpAddress == NULL) {
            LOGI("arm jump address null.");
            break;
        }

        /* LDR PC, [PC, #-4]的机器码是0xE51FF004 */
        BYTE szLdrPCOpcodes[8] = {0x04, 0xF0, 0x1F, 0xE5};
        memcpy(szLdrPCOpcodes + 4, &pJumpAddress, 4);
        memcpy(pCurAddress, szLdrPCOpcodes, 8);
        /* 刷新缓存中的指令，防止缓存中指令未进行修改引起的错误*/
        cacheflush(*((uint32_t *) pCurAddress), 8, 0);

        bRet = true;
        break;
    }

    return bRet;
}

/**
 *  ARM：构造原指令函数。申请一块内存，写入原指令和跳转指令
 *      * 执行原指令
 *      * 跳转到原始指令流程中，即原指令的下一条指令处
 *  出了上面两个功能我们还需要将shellcode中的原指令函数地址进行填充，补全桩函数中原指令函数地址
 *
 *  @param  pstInlineHook   hook点相关信息的结构体
 *  @return bool            原指令函数是否构造成功
 */
bool BuildArmOldFunction(ARM_INLINE_HOOK_INFO *pstInlineHook) {
    bool bRet = false;

    while (1) {
        if (pstInlineHook == NULL) {
            LOGI("build old function , arm pstInlineHook is null");
            break;
        }

        /* 8字节原指令，8字节原指令的下一条指令*/
        void *pNewEntryForOldFunction = malloc(16);
        if (pNewEntryForOldFunction == NULL) {
            LOGI("arm new entry for old function malloc fail.");
            break;
        }

        if (ChangePageProperty(pNewEntryForOldFunction, 16) == false) {
            LOGI("arm change new entry page property fail.");
            break;
        }

        /* 拷贝原指令到内存块中*/
        memcpy(pNewEntryForOldFunction, pstInlineHook->szbyBackupOpcodes, 8);
        /* 拷贝跳转指令到内存块中*/
        if (BuildArmJumpCode(pNewEntryForOldFunction + 8, pstInlineHook->pHookAddr + 8) == false) {
            LOGI("arm build jump opcodes for new entry fail.");
            break;
        }

        /* 填充shellcode里stub的回调地址*/
        *(pstInlineHook->ppOldFuncAddr) = pNewEntryForOldFunction;

        bRet = true;
        break;
    }

    return bRet;
}

/**
 *  ARM：覆盖HOOK点的指令，跳转到桩函数的位置
 *
 *  @param  pstInlineHook   inlinehook信息
 *  @return bool            原地跳转指令是否构造成功
 */
bool RebuildArmHookTarget(ARM_INLINE_HOOK_INFO *pstInlineHook) {
    bool bRet = false;

    while (1) {
        if (pstInlineHook == NULL) {
            LOGI("arm cover old instructions, pstInlineHook is null");
            break;
        }

        /* 修改原位置的页属性，保证可写*/
        if (ChangePageProperty(pstInlineHook->pHookAddr, 8) == false) {
            LOGI("arm change page property error.");
            break;
        }

        /* 覆盖原指令为跳转指令*/
        if (BuildArmJumpCode(pstInlineHook->pHookAddr, pstInlineHook->pStubShellCodeAddr) ==
            false) {
            LOGI("arm build jump opcodes for new entry fail.");
            break;
        }

        bRet = true;
        break;
    }

    return bRet;
}

/**
 *  ARM：恢复原指令，删除hook点
 *
 *  @param  pstInlineHook   inlinehook信息
 *  @return bool            删除hook点是否成功
 */
bool RestoreArmHookTarget(ARM_INLINE_HOOK_INFO *pstInlineHook) {
    bool bRet = false;

    while (1) {
        if (pstInlineHook == NULL) {
            LOGI("arm cover old instructions, pstInlineHook is null");
            break;
        }

        /* 修改原位置的页属性，保证可写*/
        if (ChangePageProperty(pstInlineHook->pHookAddr, 8) == false) {
            LOGI("arm change page property error.");
            break;
        }

        if (InitArmHookInfo(pstInlineHook) == false) {
            LOGI("arm pstInlineHook is null.");
            break;
        }
        /* 恢复原指令*/
        memcpy(pstInlineHook->pHookAddr, pstInlineHook->szbyBackupOpcodes, 8);
        cacheflush(*((uint32_t *) pstInlineHook->pHookAddr), 8, 0);

        bRet = true;
        break;
    }

    return bRet;
}

/**
 *  ARM：对外提供Hook函数的调用接口。
 *
 *  @param  pstInlineHook   inlinehook信息
 *  @return bool            是否hook成功
 */
bool HookArm(ARM_INLINE_HOOK_INFO *pstInlineHook) {
    bool bRet = false;

    while (1) {
        if (pstInlineHook == NULL) {
            LOGI("arm pstInlineHook is null.");
            break;
        }

        /* 初始化hook点的信息，将原指令地址处的指令内容存放到hook点结构体中*/
        if (InitArmHookInfo(pstInlineHook) == false) {
            LOGI("Init Arm HookInfo fail.");
            break;
        }

        /* 1. 构造桩函数*/
        if (BuildArmStub(pstInlineHook) == false) {
            LOGI("Arm BuildStub fail.");
            break;
        }
        LOGI("ARM BuildStub completed.");

        /* 2. 构造原指令函数，执行被覆盖指令并跳转回原始指令流程*/
        if (BuildArmOldFunction(pstInlineHook) == false) {
            LOGI("BuildArmOldFunction fail.");
            break;
        }
        LOGI("BuildArmOldFunction completed.");

        /* 3. 改写原指令为跳转指令，跳转到桩函数处*/
        if (RebuildArmHookTarget(pstInlineHook) == false) {
            LOGI("RebuildHookAddress fail.");
            break;
        }
        LOGI("RebuildArmHookAddress completed.");

        bRet = true;
        break;
    }

    return bRet;
}

/**
 *  Thumb-2：初始化Hook点信息，根据用户指定位置，将该处的指令存进hook点结构体中
 *
 *  @param  pstInlineHook   hook点信息的结构体
 *  @return bool            是否初始化成功
 */
bool InitThumbHookInfo(THUMB_INLINE_HOOK_INFO *pstInlineHook) {
    bool bRet = false;
    int backUpPos = 0;
    uint16_t *currentOpcode = pstInlineHook->pHookAddr-1;
    int cnt = 0;
    int is_thumb32_count=0;

    for(int i=0;i<BACKUP_CODE_NUM_MAX;i++){
        pstInlineHook->backUpFixLengthList[i] = -1;
    }

    if(pstInlineHook == NULL)
    {
        LOGI("pstInlineHook is null");
        return bRet;
    }

    uint16_t *p11;

    //判断最后由(pHookAddr-1)[10:11]组成的thumb命令是不是thumb32，
    //如果是的话就需要备份14byte或者10byte才能使得汇编指令不被截断。由于跳转指令在补nop的情况下也只需要10byte，
    //所以就取pstInlineHook->backUpLength为10

    for (int k=5;k>=0;k--){
        p11 = pstInlineHook->pHookAddr-1+k*2;
        LOGI("P11 : %x",*p11);
        if(isThumb32(*p11)){
            is_thumb32_count += 1;
        }else{
            break;
        }
    }

    LOGI("is_thumb32_count : %d",is_thumb32_count);

    if(is_thumb32_count%2==1)
    {
        LOGI("The last ins is thumb32. Length will be 10.");
        pstInlineHook->backUpLength = 10;
    }
    else{
        LOGI("The last ins is not thumb32. Length will be 12.");
        pstInlineHook->backUpLength = 12;
    }

    //修正：否则szbyBackupOpcodes会向后偏差1 byte
    memcpy(pstInlineHook->szbyBackupOpcodes, pstInlineHook->pHookAddr-1, pstInlineHook->backUpLength);

    while(1)
    {
        LOGI("Hook Info Init");
        //int cnt=0;
        if(isThumb32(*currentOpcode))
        {
            LOGI("cnt %d thumb32",cnt);
            uint16_t *currentThumb32high = currentOpcode;
            uint16_t *currentThumb32low = currentOpcode+1;
            uint32_t instruction;
            int fixLength;

            instruction = (*currentThumb32high<<16) | *currentThumb32low;
            fixLength = lengthFixThumb32(instruction);
            LOGI("fixLength : %d",fixLength);
            pstInlineHook->backUpFixLengthList[cnt++] = 1; //说明是个thumb32
            pstInlineHook->backUpFixLengthList[cnt++] = fixLength - 1;
            backUpPos += 4;
        }
        else{
            LOGI("cnt %d thumb16",cnt);
            uint16_t instruction = *currentOpcode;
            int fixLength;
            fixLength = lengthFixThumb16(instruction);
            LOGI("fixLength : %d",fixLength);
            pstInlineHook->backUpFixLengthList[cnt++] = fixLength;
            backUpPos += 2;
        }

        if (backUpPos < pstInlineHook->backUpLength)
        {
            currentOpcode = pstInlineHook->pHookAddr -1 + sizeof(uint8_t)*backUpPos;
            LOGI("backUpPos : %d", backUpPos);
        }
        else{
            return true;
        }
    }

    return false;
}

/**
 *  Thumb-2：构造桩函数
 *
 *  @param  pstInlineHook   hook点信息的结构体
 *  @return bool            是否构造成功
 */
bool BuildThumbStub(THUMB_INLINE_HOOK_INFO *pstInlineHook) {
    bool bRet = false;

    while(1)
    {
        if(pstInlineHook == NULL)
        {
            LOGI("pstInlineHook is null");
            break;
        }

        void *p_shellcode_start_s = &_shellcode_start_s_thumb;
        void *p_shellcode_end_s = &_shellcode_end_s_thumb;
        void *p_hookstub_function_addr_s = &_hookstub_function_addr_s_thumb;
        void *p_old_function_addr_s = &_old_function_addr_s_thumb;

        size_t sShellCodeLength = p_shellcode_end_s - p_shellcode_start_s;
        //malloc一段新的stub代码
        void *pNewShellCode = malloc(sShellCodeLength);
        if(pNewShellCode == NULL)
        {
            LOGI("shell code malloc fail.");
            break;
        }
        memcpy(pNewShellCode, p_shellcode_start_s, sShellCodeLength);
        //更改stub代码页属性，改成可读可写可执行
        if(ChangePageProperty(pNewShellCode, sShellCodeLength) == false)
        {
            LOGI("change shell code page property fail.");
            break;
        }

        //设置跳转到外部stub函数去
        void **ppHookStubFunctionAddr = pNewShellCode + (p_hookstub_function_addr_s - p_shellcode_start_s);
        *ppHookStubFunctionAddr = pstInlineHook->onCallBack;

        //备份外部stub函数运行完后跳转的函数地址指针，用于填充老函数的新地址
        pstInlineHook->ppOldFuncAddr  = pNewShellCode + (p_old_function_addr_s - p_shellcode_start_s); //打算对它+1

        //填充shellcode地址到hookinfo中，用于构造hook点位置的跳转指令
        pstInlineHook->pStubShellCodeAddr = pNewShellCode;

        bRet = true;
        break;
    }

    return bRet;
}

/**
 *  Thumb-2：构造Thumb指令集的函数跳转
 *
 *  @param  pCurAddress      当前地址，要构造跳转指令的位置
 *  @param  pJumpAddress     目的地址，要从当前位置跳过去的地址
 *  @return bool             跳转指令是否构造成功
 */
bool BuildThumbJumpCode(void *pCurAddress, void *pJumpAddress) {
    bool bRet = false;
    while(1)
    {
        if(pCurAddress == NULL || pJumpAddress == NULL)
        {
            LOGI("address null.");
            break;
        }
        //LDR PC, [PC, #0]
        //addr
        //LDR PC, [PC, #0]对应的thumb机器码为：0xf004f85f//arm下LDR PC, [PC, #-4]为0xE51FF004
        //addr为要跳转的地址。该跳转指令范围为32位，对于32位系统来说即为全地址跳转。
        //缓存构造好的跳转指令（ARM下32位，两条指令只需要8个bytes）
        //对于目标代码是thumb-2指令集来说，使用固定的8或者12byte备份是肯定有问题的！因为thumb16（2byte）和thumb32（4byte）是混合使用的
        //因此，当备份12byte时，如果目标是2+2+2+2+2+4，那就会把最后的那个thumb32截断。
        //当备份8byte时，如果目标是2+4+4，也会把最后的thumb32截断
        if (CLEAR_BIT0((uint32_t)pCurAddress) % 4 != 0) {
            //((uint16_t *) CLEAR_BIT0(pCurAddress))[i++] = 0xBF00;  // NOP
            BYTE szLdrPCOpcodes[12] = {0x00, 0xBF, 0xdF, 0xF8, 0x00, 0xF0};
            memcpy(szLdrPCOpcodes + 6, &pJumpAddress, 4);
            memcpy(pCurAddress, szLdrPCOpcodes, 10);
            cacheflush(*((uint32_t*)pCurAddress), 10, 0);
        }
        else{
            BYTE szLdrPCOpcodes[8] = {0xdF, 0xF8, 0x00, 0xF0};
            //将目的地址拷贝到跳转指令缓存位置
            memcpy(szLdrPCOpcodes + 4, &pJumpAddress, 4);
            memcpy(pCurAddress, szLdrPCOpcodes, 8);
            cacheflush(*((uint32_t*)pCurAddress), 8, 0);
        }


        bRet = true;
        break;
    }
    return bRet;
}

/**
 *  Thumb-2：构造原指令函数
 *
 *  @param  pstInlineHook   hook点相关信息的结构体
 *  @return bool            原指令函数是否构造成功
 */
bool BuildThumbOldFunction(THUMB_INLINE_HOOK_INFO *pstInlineHook) {
    bool bRet = false;

    void *fixOpcodes;
    int fixLength;

    fixOpcodes = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);

    while(1)
    {
        if(pstInlineHook == NULL)
        {
            LOGI("pstInlineHook is null");
            break;
        }

        //12个bytes存放原来的thumb opcodes，另外8个bytes存放跳转回hook点下面的跳转指令
        void * pNewEntryForOldFunction = malloc(200);
        if(pNewEntryForOldFunction == NULL)
        {
            LOGI("new entry for old function malloc fail.");
            break;
        }

        pstInlineHook->pNewEntryForOldFunction = pNewEntryForOldFunction;

        if(ChangePageProperty(pstInlineHook->pNewEntryForOldFunction, 200) == false)
        {
            LOGI("change new entry page property fail.");
            break;
        }

        fixLength = fixPCOpcodeThumb(fixOpcodes, pstInlineHook); //修复PC相关指令
        //返回修复后opcode的指令长度，修复后的指令保存在fixOpcode中
        memcpy(pNewEntryForOldFunction, fixOpcodes, fixLength);
        //memcpy(pNewEntryForOldFunction, pstInlineHook->szbyBackupOpcodes, pstInlineHook->backUpLength);
        LOGI("pHookAddr : %x",pstInlineHook->pHookAddr);
        LOGI("backupLength : %x",pstInlineHook->backUpLength);
        //填充跳转指令
        if(BuildThumbJumpCode(pNewEntryForOldFunction + fixLength, pstInlineHook->pHookAddr + pstInlineHook->backUpLength) == false)
        {
            LOGI("build jump opcodes for new entry fail.");
            break;
        }
        //填充shellcode里stub的回调地址
        *(pstInlineHook->ppOldFuncAddr) = pNewEntryForOldFunction;

        bRet = true;
        break;
    }

    return bRet;
}

/**
 *  Thumb：覆盖原指令
 *
 *  @param  pstInlineHook   inlinehook信息
 *  @return bool            原地跳转指令是否构造成功
 */
bool RebuildThumbHookTarget(THUMB_INLINE_HOOK_INFO *pstInlineHook) {
    bool bRet = false;

    while(1)
    {
        if(pstInlineHook == NULL)
        {
            LOGI("pstInlineHook is null");
            break;
        }
        //修改原位置的页属性，保证可写
        if(ChangePageProperty(pstInlineHook->pHookAddr, 8) == false)
        {
            LOGI("change page property error.");
            break;
        }
        //填充跳转指令
        if(BuildThumbJumpCode(pstInlineHook->pHookAddr-1, pstInlineHook->pStubShellCodeAddr) == false)
        {
            LOGI("build jump opcodes for new entry fail.");
            break;
        }
        bRet = true;
        break;
    }

    return bRet;
}

/**
 *  Thumb：删除hook点，恢复原指令
 *
 *  @param  pstInlineHook   inlinehook信息
 *  @return bool            删除hook点是否成功
 */
bool RestoreThumbHookTarget(THUMB_INLINE_HOOK_INFO *pstInlineHook) {
    bool bRet = false;

    while (1) {
        if (pstInlineHook == NULL) {
            LOGI("Thumb cover old instructions, pstInlineHook is null");
            break;
        }

        if (ChangePageProperty(pstInlineHook->pHookAddr, pstInlineHook->backUpLength) == false) {
            LOGI("Thumb change page property error.");
            break;
        }

        memcpy(pstInlineHook->pHookAddr, pstInlineHook->szbyBackupOpcodes,
               pstInlineHook->backUpLength);
        cacheflush(*((uint32_t *) pstInlineHook->pHookAddr), pstInlineHook->backUpLength, 0);

        bRet = true;
        break;
    }

    return bRet;
}

/**
 *  Thumb：对外提供hook的入口函数
 *
 *  @param  pstInlineHook   inlinehook信息
 *  @return bool            是否hook成功
 */
bool HookThumb(THUMB_INLINE_HOOK_INFO *pstInlineHook) {
    bool bRet = false;
    LOGI("HookThumb()");

    while(1)
    {
        //LOGI("pstInlineHook is null 1.");
        if(pstInlineHook == NULL)
        {
            LOGI("pstInlineHook is null.");
            break;
        }

        //LOGI("Init Thumb HookInfo fail 1.");
        //设置ARM下inline hook的基础信息
        if(InitThumbHookInfo(pstInlineHook) == false)
        {
            LOGI("Init Arm HookInfo fail.");
            break;
        }

        //LOGI("BuildStub fail 1.");
        //构造stub，功能是保存寄存器状态，同时跳转到目标函数，然后跳转回原函数
        //需要目标地址，返回stub地址，同时还有old指针给后续填充
        if(BuildThumbStub(pstInlineHook) == false)
        {
            LOGI("BuildStub fail.");
            break;
        }

        //LOGI("BuildOldFunction fail 1.");
        //负责重构原函数头，功能是修复指令，构造跳转回到原地址下
        //需要原函数地址
        if(BuildThumbOldFunction(pstInlineHook) == false)
        {
            LOGI("BuildOldFunction fail.");
            break;
        }

        //LOGI("RebuildHookAddress fail 1.");
        //负责重写原函数头，功能是实现inline hook的最后一步，改写跳转
        //需要cacheflush，防止崩溃
        if(RebuildThumbHookTarget(pstInlineHook) == false)
        {
            LOGI("RebuildHookAddress fail.");
            break;
        }
        bRet = true;
        break;
    }

    return bRet;
}
