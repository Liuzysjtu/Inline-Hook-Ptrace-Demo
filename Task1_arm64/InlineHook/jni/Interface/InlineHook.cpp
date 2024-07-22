#include <vector>

extern "C"
{
#include "InlineHook.h"
}

//声明函数在加载库时被调用,也是hook的主函数
void ModifyIBored() __attribute__((constructor));

typedef std::vector<INLINE_HOOK_INFO *> InlineHookInfoPVec;
static InlineHookInfoPVec gs_vecInlineHookInfo;     //管理HOOK点

/**
 *  对外inline hook接口，负责管理inline hook信息
 *  @param  pHookAddr     要hook的地址
 *  @param  onCallBack    要插入的回调函数
 *  @return inlinehook是否设置成功（已经设置过，重复设置返回false）
 */
bool InlineHook(void *pHookAddr, void (*onCallBack)(struct user_pt_regs *)) {
    bool bRet = false;

    if (pHookAddr == NULL || onCallBack == NULL) {
        return bRet;
    }

    //填写hook点位置和用户自定义回调函数
    INLINE_HOOK_INFO *pstInlineHook = new INLINE_HOOK_INFO();
    pstInlineHook->pHookAddr = pHookAddr;
    pstInlineHook->onCallBack = onCallBack;

    if(HookArm(pstInlineHook) == false)
    {
        LOGI("HookArm fail.");
        delete pstInlineHook;
        return bRet;
    }


    gs_vecInlineHookInfo.push_back(pstInlineHook);

    return true;
}

/**
 *  用户自定义的回调函数，修改r2寄存器为11
 */
void EvilHookStubFunctionForIBored(user_pt_regs *regs) {
    LOGI("In Evil Hook Stub.");
    regs->regs[9] = 0x1;
}

/**
 *  1.Hook入口
 */
void ModifyIBored() {
    int target_offset = 0x734; //*想Hook的目标在目标so中的偏移*

    LOGI("In IHook's ModifyIBored.");

    void *pModuleBaseAddr = GetModuleBaseAddr(-1, "libIBored.so");

    LOGI("libIBored.so base addr is 0x%X.", pModuleBaseAddr);
    if (pModuleBaseAddr == 0) {
        LOGI("get module base error.");
        return;
    }

    //模块基址加上HOOK点的偏移地址就是HOOK点在内存中的位置
    uint64_t uiHookAddr = (uint64_t) pModuleBaseAddr + target_offset;

    LOGI("uiHookAddr is %X in arm64 mode", uiHookAddr);


    //HOOK函数
    InlineHook((void *) (uiHookAddr), EvilHookStubFunctionForIBored);
}

