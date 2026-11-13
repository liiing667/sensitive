package com.github.houbb.sensitive.core.support.scan;

import com.github.houbb.chars.scan.api.CharsScanContext;
import com.github.houbb.chars.scan.api.ICharsScan;
import com.github.houbb.chars.scan.api.ICharsScanFactory;

import java.util.List;

/**
 * 默认失败关闭的扫描工厂。
 *
 * <p>仅包装单个 {@link ICharsScan} 的执行：某个自定义扫描器抛异常时跳过该扫描器，
 * 其余扫描器仍按 {@link #scanTypeList()} 的原顺序继续工作，保证成功的规则不受影响。
 * 工厂结构本身的异常向上抛出，由 {@link FailClosedCharsCore} 统一兜底。</p>
 *
 * @author dh
 * @since 1.9.1
 */
public class FailClosedCharsScanFactory implements ICharsScanFactory {

    private final ICharsScanFactory delegate;

    public FailClosedCharsScanFactory(ICharsScanFactory delegate) {
        if (delegate == null) {
            throw new IllegalArgumentException("delegate must not be null");
        }
        this.delegate = delegate;
    }

    @Override
    public List<String> scanTypeList() {
        return delegate.scanTypeList();
    }

    @Override
    public ICharsScan getCharScan(String scanType) {
        return new FailClosedCharsScan(delegate.getCharScan(scanType));
    }

    @Override
    public List<ICharsScan> allCharScanList() {
        List<ICharsScan> scans = delegate.allCharScanList();
        for (int i = 0; i < scans.size(); i++) {
            scans.set(i, new FailClosedCharsScan(scans.get(i)));
        }
        return scans;
    }

    /**
     * 单个扫描器失败时跳过自身，不影响同批次的其他扫描器。
     */
    private static class FailClosedCharsScan implements ICharsScan {

        private final ICharsScan delegate;

        private volatile boolean failureReported;

        private FailClosedCharsScan(ICharsScan delegate) {
            this.delegate = delegate;
        }

        @Override
        public void scan(int index, char currentChar, char[] chars,
                         CharsScanContext context) {
            try {
                delegate.scan(index, currentChar, chars, context);
            } catch (RuntimeException e) {
                if (!failureReported) {
                    failureReported = true;
                    reportScanFailure(delegate.getClass().getName(), e);
                }
            }
        }

        @Override
        public List<com.github.houbb.chars.scan.api.CharsScanMatchItem> getMatchList() {
            return delegate.getMatchList();
        }

        @Override
        public String getScanType() {
            return delegate.getScanType();
        }

        @Override
        public int getPriority() {
            return delegate.getPriority();
        }

        @Override
        public void clear() {
            delegate.clear();
        }

    }

    private static void reportScanFailure(String scannerName, RuntimeException e) {
        System.err.println(
                "[ERROR] Custom sensitive scanner <" + scannerName
                        + "> failed and was skipped for the current message: "
                        + e.getClass().getName() + ": " + e.getMessage());
    }

}
