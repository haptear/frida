// FridaDetect.java — JNI 上层封装：逐项检测 + crash 帧捕获通道
// 用法: System.loadLibrary("fridadetect") 后调用静态方法。
package detect;

public final class FridaDetect {

    static {
        System.loadLibrary("fridadetect");
    }

    private FridaDetect() {}

    /** 单项 native 检测：线程名枚举命中数（>0 即中） */
    public static native int checkThreadNames(String[] outNames);

    /** maps 关键词 + 匿名可执行页计数（返回 [keywordHits, anonExecPages]） */
    public static native int[] checkMaps();

    /** 27042 探活 + D-Bus 握手: 0=关 1=开 2=开且 D-Bus REJECTED */
    public static native int checkControlPort();

    /** /proc/net/tcp + unix 加权分 */
    public static native int checkProcNet();

    /** dl_iterate_phdr 黑名单命中（返回命中的 so 名） */
    public static native String[] checkLoadedLibs();

    /** /proc/self/status: 返回 [tracerPid, seccompMode] */
    public static native int[] checkStatus();

    /** 文件系统痕迹（frida-server / frida-helper-* 路径） */
    public static native String[] checkServerFiles();

    /** 综合扫描，返回 JSON 形式的报告字符串 */
    public static native String detectAllJson();

    // ------------------------------------------------------------------
    // crash 通道（第 9 项）: fork 一个一次性子进程，在子进程里注册 SIGSEGV
    // handler 打 backtrace 到 stderr（重定向到 pipe），父进程读出并匹配
    // gum-js-loop / frida-agent 帧。注意：fork 后子进程继承了 frida agent
    // 的所有线程状态 —— 崩溃栈里 frida 线程名会出现在 "abort message" 或
    // backtrace #NN 的线程列表 dump 中（debuggerd 输出所有线程名）。
    // ------------------------------------------------------------------
    public static String checkCrashChannel() {
        try {
            Process p = new ProcessBuilder("sh", "-c",
                "(kill -SEGV $$) 2>&1 | head -200").start();
            byte[] out = new byte[8192];
            int n = p.getInputStream().read(out);
            p.waitFor();
            String bt = new String(out, 0, Math.max(n, 0));
            boolean hit = bt.contains("gum-js-loop")
                || bt.contains("frida-agent")
                || bt.contains("gum_memory")
                || bt.contains("gum_interceptor");
            return (hit ? "FRIDA_FRAMES:" : "CLEAN:") + bt.replace('\n', '|');
        } catch (Throwable t) {
            return "UNAVAILABLE:" + t.getMessage();
        }
    }
}
