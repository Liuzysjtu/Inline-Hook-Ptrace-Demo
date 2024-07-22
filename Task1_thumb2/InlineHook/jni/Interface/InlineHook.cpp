#include <vector>

extern "C"
{
#include "InlineHook.h"
}

//声明函数在加载库时被调用,也是hook的主函数
void Modify2048() __attribute__((constructor));

typedef std::vector<THUMB_INLINE_HOOK_INFO *> InlineHookInfoPVec;
//typedef std::vector<ARM_INLINE_HOOK_INFO*> InlineHookInfoPVec;
static InlineHookInfoPVec gs_vecInlineHookInfo;     //管理HOOK点

/**
 *  对外inline hook接口，负责管理inline hook信息
 *  @param  pHookAddr     要hook的地址
 *  @param  onCallBack    要插入的回调函数
 *  @return inlinehook是否设置成功（已经设置过，重复设置返回false）
 */
bool InlineHook(void *pHookAddr, void (*onCallBack)(struct pt_regs *)) {
    bool bRet = false;

    if (pHookAddr == NULL || onCallBack == NULL) {
        return bRet;
    }

    //填写hook点位置和用户自定义回调函数
    THUMB_INLINE_HOOK_INFO *pstInlineHook = new THUMB_INLINE_HOOK_INFO();
//    ARM_INLINE_HOOK_INFO *pstInlineHook = new ARM_INLINE_HOOK_INFO();
    pstInlineHook->pHookAddr = pHookAddr;
    pstInlineHook->onCallBack = onCallBack;

//    if(HookArm(pstInlineHook) == false)
//    {
//        LOGI("HookArm fail.");
//        delete pstInlineHook;
//        return bRet;
//    }

    LOGI("In InlineHook.");

    if (HookThumb(pstInlineHook) == false) {
        LOGI("HookThumb fail.");
        delete pstInlineHook;
        return bRet;
    }

    gs_vecInlineHookInfo.push_back(pstInlineHook);
    LOGI("HookThumb completed.");
    return true;
}

/**
 *  用户自定义的回调函数，修改r2寄存器为11
 */
void EvilHookStubFunctionFor2048_1(pt_regs *regs) {
    LOGI("In Evil Hook Stub.");
    regs->uregs[2] = 0xA;
    regs->uregs[3] = 0x0;
}

void EvilHookStubFunctionFor2048_2(pt_regs *regs) {
    LOGI("In Evil Hook Stub.");
    regs->uregs[3] = 0x1;
}

/**
 *  1.Hook入口
 */
void Modify2048() {
    uint32_t Method1 = 0x000a1ce4;
    uint32_t Method2 = 0x000a1a4a;

    LOGI("In IHook's Modify2048.");
    bool is_target_thumb = true; //*目标是否是thumb模式？*
    void *pModuleBaseAddr = GetModuleBaseAddr(-1, "libcocos2dcpp.so");
    LOGI("libcocos2dcpp.so base addr is 0x%X.", pModuleBaseAddr);
    if (pModuleBaseAddr == 0) {
        LOGI("get module base error.");
        return;
    }

    //模块基址加上HOOK点的偏移地址就是HOOK点在内存中的位置
    uint32_t uiHookAddr = (uint32_t) pModuleBaseAddr + Method1;
    if(is_target_thumb){ //之所以人来判断那是因为Native Hook之前肯定是要逆向分析一下的，那时候就能知道是哪种模式。而且自动识别arm和thumb比较麻烦。
        uiHookAddr++;
        LOGI("uiHookAddr is %X in thumb mode", uiHookAddr);
    }
    else{
        LOGI("uiHookAddr is %X in arm mode", uiHookAddr);
    }

    //HOOK函数
    InlineHook((void *) (uiHookAddr), EvilHookStubFunctionFor2048_1);
}

