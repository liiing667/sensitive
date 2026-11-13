package com.github.houbb.sensitive.core.support.scan;

import com.github.houbb.chars.scan.api.CharsScanContext;
import com.github.houbb.chars.scan.api.CharsScanMatchItem;
import com.github.houbb.chars.scan.api.ICharsReplace;
import com.github.houbb.chars.scan.api.ICharsReplaceFactory;

/**
 * 默认失败关闭的替换工厂。
 *
 * <p>仅包装单个 {@link ICharsReplace} 的执行：某个替换策略失败时，用固定脱敏标记
 * 替换当前命中区间，而不是把命中的原文写进日志；其他命中区间的策略照常执行。</p>
 *
 * @author dh
 * @since 1.9.1
 */
public class FailClosedCharsReplaceFactory implements ICharsReplaceFactory {

    private final ICharsReplaceFactory delegate;

    public FailClosedCharsReplaceFactory(ICharsReplaceFactory delegate) {
        if (delegate == null) {
            throw new IllegalArgumentException("delegate must not be null");
        }
        this.delegate = delegate;
    }

    @Override
    public ICharsReplace getReplace(String scanType) {
        return new FailClosedCharsReplace(delegate.getReplace(scanType));
    }

    /**
     * 替换策略失败时把当前命中区间整体改写为固定脱敏标记。
     */
    private static class FailClosedCharsReplace implements ICharsReplace {

        private final ICharsReplace delegate;

        private FailClosedCharsReplace(ICharsReplace delegate) {
            this.delegate = delegate;
        }

        @Override
        public void replace(StringBuilder stringBuilder, char[] chars,
                            CharsScanMatchItem matchItem,
                            CharsScanContext context) {
            try {
                delegate.replace(stringBuilder, chars, matchItem, context);
            } catch (RuntimeException e) {
                reportReplaceFailure(e);
                stringBuilder.append(SensitiveScanBsContext.FAIL_CLOSED_MASK);
            }
        }

        @Override
        public String getScanType() {
            return delegate.getScanType();
        }

    }

    private static void reportReplaceFailure(RuntimeException e) {
        System.err.println(
                "[ERROR] Custom sensitive replace strategy failed, fixed mask used: "
                        + e.getClass().getName() + ": " + e.getMessage());
    }

}
