#include "lib.hpp"
#include <cmath>
#include <cstdint>

// ======================== 逆向RVA/偏移（和Ghidra/GDB调试版本严格对齐） ========================
constexpr uintptr_t OFFSET_GYRO_MGR        = 0x147FB30;
constexpr uintptr_t HOOK_TARGET_RVA        = 0x3D1D4C;

constexpr uint32_t MGR_OFF_GX              = 0x17D8;
constexpr uint32_t MGR_OFF_GY              = 0x17DC;
constexpr uint32_t MGR_OFF_BTN             = 0x1820;
constexpr uint32_t BIT_ZL                  = 0x100U;

// ======================== 配置常量 ========================
struct GyroConfig
{
    float   gain_x      = 4096.0f;
    float   gain_y      = 4096.0f;
    int32_t clamp_max   = 12000;
    uint32_t inv_x      = 0U;
    uint32_t inv_y      = 0U;
} g_cfg;

static inline int32_t clamp_i32(int32_t v, int32_t lo, int32_t hi)
{
    if(v < lo) return lo;
    if(v > hi) return hi;
    return v;
}

inline uintptr_t GetMainBase()
{
    return exl::util::modules::GetTargetOffset(0);
}

static bool ReadGyro(float& gx, float& gy)
{
    uintptr_t base = GetMainBase();
    uintptr_t* ppMgr = reinterpret_cast<uintptr_t*>(base + OFFSET_GYRO_MGR);
    uintptr_t mgr = *ppMgr;
    if(mgr == 0U) return false;

    gx = *reinterpret_cast<float*>(mgr + MGR_OFF_GX);
    gy = *reinterpret_cast<float*>(mgr + MGR_OFF_GY);
    return true;
}

static bool ZL_IsPressed()
{
    uintptr_t base = GetMainBase();
    uintptr_t* ppMgr = reinterpret_cast<uintptr_t*>(base + OFFSET_GYRO_MGR);
    uintptr_t mgr = *ppMgr;
    if(mgr == 0U) return false;

    uint32_t btn = *reinterpret_cast<uint32_t*>(mgr + MGR_OFF_BTN);
    return (btn & BIT_ZL) != 0U;
}

// ======================== Trampoline 带寄存器上下文Context ========================
HOOK_DEFINE_TRAMPOLINE(NpadGyroHook)
{
    static void Callback(exl::hook::Context& ctx)
    {
        // ========== 【重点：先修改栈，再执行游戏原始指令！和GDB断点顺序一致】 ==========
        if(!ZL_IsPressed())
        {
            Orig(ctx);
            return;
        }

        float gx = 0.0f, gy = 0.0f;
        if(!ReadGyro(gx, gy))
        {
            Orig(ctx);
            return;
        }

        int32_t delta_x = static_cast<int32_t>(gx * g_cfg.gain_x);
        int32_t delta_y = static_cast<int32_t>(gy * g_cfg.gain_y);

        if(g_cfg.inv_x) delta_x = -delta_x;
        if(g_cfg.inv_y) delta_y = -delta_y;

        delta_x = clamp_i32(delta_x, -g_cfg.clamp_max, g_cfg.clamp_max);
        delta_y = clamp_i32(delta_y, -g_cfg.clamp_max, g_cfg.clamp_max);

        // ctx.sp = 劫持瞬间真实栈指针，等价GDB的sp
        uintptr_t sp = ctx.sp;
        int16_t* stick_x = reinterpret_cast<int16_t*>(sp + 0x48);
        int16_t* stick_y = reinterpret_cast<int16_t*>(sp + 0x4C);

        int32_t new_x = static_cast<int32_t>(*stick_x) + delta_x;
        int32_t new_y = static_cast<int32_t>(*stick_y) + delta_y;

        new_x = clamp_i32(new_x, -32767, 32767);
        new_y = clamp_i32(new_y, -32767, 32767);

        *stick_x = static_cast<int16_t>(new_x);
        *stick_y = static_cast<int16_t>(new_y);

        // 修改完成，放行原始指令
        Orig(ctx);
    }
};

extern "C" void exl_main(void* x0, void* x1)
{
    exl::hook::Initialize();
    NpadGyroHook::InstallAtOffset(HOOK_TARGET_RVA);
}

extern "C" void exl_exception_entry(void* /*regs*/)
{
    while(true);
}
namespace exl::exception { struct ExceptionInfo; }
extern "C" void exl_exception_handler(exl::exception::ExceptionInfo* /*info*/)
{
    while(true);
}
