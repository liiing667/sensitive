package com.github.houbb.sensitive.core.support.scan;

import com.github.houbb.chars.scan.api.CharsScanContext;
import com.github.houbb.chars.scan.api.ICharsCore;

/**
 * 默认失败关闭的扫描核心。
 *
 * <p>底层扫描或替换抛出任何异常时，不再把原文透传到日志，而是返回固定脱敏标记，
 * 避免手机号、证件号、口令等敏感信息在故障期间泄露。正常路径完全委托给被包装的
 * {@link ICharsCore}，成功命中的规则仍按原顺序处理。</p>
 *
 * @author dh
 * @since 1.9.1
 */
public class FailClosedCharsCore implements ICharsCore {

    private final ICharsCore delegate;

    public FailClosedCharsCore(ICharsCore delegate) {
        if (delegate == null) {
            throw new IllegalArgumentException("delegate must not be null");
        }
        this.delegate = delegate;
    }

    @Override
    public String scanAndReplace(String originalString, CharsScanContext context) {
        try {
            return delegate.scanAndReplace(originalString, context);
        } catch (Exception e) {
            reportFailure(e);
            return SensitiveScanBsContext.maskOnFailure(originalString);
        }
    }

    private static void reportFailure(Exception e) {
        System.err.println(
                "[ERROR] Sensitive scan failed, fallback to fixed mask: "
                        + e.getClass().getName() + ": " + e.getMessage());
    }

}
