package com.github.houbb.sensitive.core.support.scan;

import com.github.houbb.chars.scan.bs.CharsScanBs;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

/**
 * 日志插件共用的敏感信息扫描上下文。
 *
 * <p>log4j2 和 logback 均通过这里加载同一份配置，并由
 * {@link SensitiveScanBsBuilder} 对齐 {@link CharsScanBs} 的扩展点。</p>
 *
 * @author dh
 * @since 1.9.0
 */
public final class SensitiveScanBsContext {

    private static final String CONFIG_FILE_NAME =
            "chars-scan-config.properties";

    /**
     * 扫描、替换或配置加载失败时输出的固定脱敏标记。
     *
     * <p>故障期间绝不返回原文，避免手机号、证件号、口令等敏感信息写入日志。</p>
     */
    public static final String FAIL_CLOSED_MASK = "******";

    private static volatile CharsScanBs charsScanBs;

    private static volatile boolean initialized;

    private SensitiveScanBsContext() {
    }

    /**
     * 初始化上下文。
     *
     * <p>配置损坏时默认失败关闭：保留上一次可用的共享扫描器；首次初始化即失败时，
     * 使用内置默认配置构建扫描器（同样带失败关闭包装），畸形配置不会污染共享实例。</p>
     */
    public static void init() {
        if (initialized) {
            return;
        }

        synchronized (SensitiveScanBsContext.class) {
            if (initialized) {
                return;
            }

            CharsScanBs previous = charsScanBs;
            try {
                CharsScanBs candidate = buildFailClosed(loadConfig());
                charsScanBs = candidate;
            } catch (Exception e) {
                System.err.println(
                        "[ERROR] Failed to initialize sensitive scanner: "
                                + e.getClass().getName() + ": " + e.getMessage());
                if (previous == null) {
                    charsScanBs = buildDefaultFailClosed(e);
                }
                // previous != null 时保留原共享实例，畸形配置不会污染它。
            }
            initialized = true;
        }
    }

    /**
     * 扫描并替换敏感信息。
     *
     * @param text 原文
     * @return 脱敏结果；扫描或替换失败时返回固定脱敏标记，绝不返回原文
     */
    public static String scanAndReplace(String text) {
        if (text == null) {
            return null;
        }

        init();

        try {
            return charsScanBs.scanAndReplace(text);
        } catch (Exception e) {
            System.err.println(
                    "[ERROR] Sensitive scan failed, fallback to fixed mask: "
                            + e.getClass().getName() + ": " + e.getMessage());
            return maskOnFailure(text);
        }
    }

    /**
     * 获取共享扫描器。
     *
     * @return 扫描器
     */
    public static CharsScanBs getCharsScanBs() {
        init();
        return charsScanBs;
    }

    /**
     * 重新加载类路径中的配置。
     *
     * <p>重载采用原子切换：新配置构建失败时继续使用当前共享扫描器，
     * 畸形配置不会污染共享实例。</p>
     */
    public static void reload() {
        reload(loadConfig());
    }

    /**
     * 使用指定配置重新加载共享扫描器。
     *
     * <p>公开入口，便于在不修改类路径配置文件的前提下验证畸形配置的
     * 原子切换行为；生产代码仍应使用 {@link #reload()} 从类路径加载。</p>
     *
     * @param config 新配置
     */
    public static void reload(Properties config) {
        synchronized (SensitiveScanBsContext.class) {
            CharsScanBs previous = charsScanBs;
            try {
                CharsScanBs candidate = buildFailClosed(config);
                charsScanBs = candidate;
            } catch (Exception e) {
                System.err.println(
                        "[ERROR] Failed to reload sensitive scanner, keep using the previous instance: "
                                + e.getClass().getName() + ": " + e.getMessage());
                charsScanBs = previous;
            }
            initialized = true;
        }
    }

    /**
     * 故障兜底输出。非空文本统一输出固定脱敏标记，空串保持原样。
     *
     * @param text 原文
     * @return 固定脱敏标记
     */
    public static String maskOnFailure(String text) {
        if (text == null) {
            return null;
        }
        if (text.isEmpty()) {
            return "";
        }
        return FAIL_CLOSED_MASK;
    }

    private static CharsScanBs buildFailClosed(Properties config) {
        return SensitiveScanBsBuilder.buildFailClosed(config);
    }

    private static CharsScanBs buildDefaultFailClosed(Exception cause) {
        try {
            return SensitiveScanBsBuilder.buildFailClosed(new Properties());
        } catch (Exception e) {
            System.err.println(
                    "[ERROR] Default sensitive scanner also failed: "
                            + e.getClass().getName() + ": " + e.getMessage());
            throw new IllegalStateException(
                    "No usable sensitive scanner and fail-closed is enabled",
                    cause);
        }
    }

    private static Properties loadConfig() {
        Properties config = new Properties();
        InputStream inputStream = SensitiveScanBsContext.class
                .getClassLoader()
                .getResourceAsStream(CONFIG_FILE_NAME);
        if (inputStream == null) {
            return config;
        }

        try (InputStream stream = inputStream;
             InputStreamReader reader =
                     new InputStreamReader(stream, StandardCharsets.UTF_8)) {
            config.load(reader);
        } catch (IOException e) {
            throw new IllegalStateException(
                    "Cannot read " + CONFIG_FILE_NAME, e);
        }
        return config;
    }

}
