package com.github.houbb.sensitive.test.scan;

import com.github.houbb.chars.scan.api.CharsScanContext;
import com.github.houbb.chars.scan.api.CharsScanMatchItem;
import com.github.houbb.chars.scan.api.ICharsReplace;
import com.github.houbb.chars.scan.api.ICharsScan;
import com.github.houbb.chars.scan.bs.CharsScanBs;
import com.github.houbb.sensitive.core.support.scan.SensitiveScanBsBuilder;
import com.github.houbb.sensitive.core.support.scan.SensitiveScanBsContext;
import org.junit.Assert;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

/**
 * 扫描与替换默认失败关闭的契约测试。
 *
 * <p>覆盖自定义扫描器抛异常、替换策略失败、畸形配置和重载原子切换，
 * 任何故障路径都不允许把手机号、证件号或口令原文写进日志。</p>
 */
public class FailClosedScanTest {

    private static final String SECRET = "13912345678";

    /**
     * 自定义扫描器抛异常时跳过自身，同批次其他规则按原顺序继续脱敏。
     */
    @Test
    public void brokenScannerIsSkippedAndOthersStillWorkTest() {
        Properties config = new Properties();
        config.setProperty(
                SensitiveScanBsBuilder.KEY_BUILT_IN_SCAN_TYPES, "1");
        config.setProperty(
                SensitiveScanBsBuilder.KEY_BUILT_IN_REPLACE_TYPES, "1");
        config.setProperty(
                SensitiveScanBsBuilder.KEY_CUSTOM_SCAN_CLASSES,
                ThrowingScan.class.getName());
        config.setProperty(
                SensitiveScanBsBuilder.KEY_SHOW_HASH, "false");

        String result = SensitiveScanBsBuilder.buildFailClosed(config)
                .scanAndReplace("value:" + SECRET);

        Assert.assertFalse("故障扫描器不能导致手机号原文泄露",
                result.contains(SECRET));
        Assert.assertEquals("value:139****5678", result);
    }

    /**
     * 替换策略失败时命中区间使用固定脱敏标记，原文不得出现。
     */
    @Test
    public void brokenReplaceUsesFixedMaskTest() {
        Properties config = new Properties();
        config.setProperty(
                SensitiveScanBsBuilder.KEY_BUILT_IN_SCAN_TYPES, "1");
        config.setProperty(
                SensitiveScanBsBuilder.KEY_BUILT_IN_REPLACE_TYPES, "1");
        config.setProperty(
                SensitiveScanBsBuilder.KEY_CUSTOM_REPLACE_CLASSES,
                ThrowingReplace.class.getName());
        config.setProperty(
                SensitiveScanBsBuilder.KEY_SHOW_HASH, "false");

        String result = SensitiveScanBsBuilder.buildFailClosed(config)
                .scanAndReplace("value:" + SECRET);

        Assert.assertFalse("故障替换策略不能导致手机号原文泄露",
                result.contains(SECRET));
        Assert.assertTrue("命中区间应输出固定脱敏标记",
                result.contains(SensitiveScanBsContext.FAIL_CLOSED_MASK));
    }

    /**
     * 整体管线抛出异常时，上下文兜底为固定脱敏标记。
     */
    @Test
    public void contextFallbackNeverReturnsRawTextTest() {
        String result = SensitiveScanBsContext.maskOnFailure(
                "password=Pa$$w0rd, idNo=11010519491231002X");
        Assert.assertEquals(SensitiveScanBsContext.FAIL_CLOSED_MASK, result);
        Assert.assertNull(SensitiveScanBsContext.maskOnFailure(null));
        Assert.assertEquals("", SensitiveScanBsContext.maskOnFailure(""));
    }

    /**
     * 畸形配置构建失败时抛出异常，由上下文失败关闭，而不是静默吞掉。
     */
    @Test
    public void malformedConfigIsRejectedByBuilderTest() {
        Properties config = new Properties();
        config.setProperty(
                SensitiveScanBsBuilder.KEY_BUILT_IN_SCAN_TYPES, "not-exist");

        try {
            SensitiveScanBsBuilder.buildFailClosed(config);
            Assert.fail("畸形配置必须快速失败，不能构建出扫描器");
        } catch (IllegalArgumentException expected) {
            // 预期行为
        }
    }

    /**
     * 不支持的哈希类型同样属于畸形配置，构建阶段必须失败。
     */
    @Test
    public void malformedHashTypeIsRejectedByBuilderTest() {
        Properties config = new Properties();
        config.setProperty(
                SensitiveScanBsBuilder.KEY_CHARS_REPLACE_HASH, "not-a-hash");

        try {
            SensitiveScanBsBuilder.buildFailClosed(config);
            Assert.fail("畸形哈希类型必须快速失败，不能构建出扫描器");
        } catch (RuntimeException expected) {
            // 预期行为
        }
    }

    /**
     * 重载畸形配置时保留上一次可用的共享实例，共享实例不被污染。
     */
    @Test
    public void reloadWithBrokenConfigKeepsPreviousInstanceTest() {
        SensitiveScanBsContext.reload();
        CharsScanBs before = SensitiveScanBsContext.getCharsScanBs();
        String beforeResult =
                SensitiveScanBsContext.scanAndReplace("value:" + SECRET);
        Assert.assertFalse(beforeResult.contains(SECRET));

        // 类路径上不存在的自定义扫描器，构建阶段必然失败。
        Properties broken = new Properties();
        broken.setProperty(
                SensitiveScanBsBuilder.KEY_CUSTOM_SCAN_CLASSES,
                "com.github.houbb.sensitive.test.DoesNotExistScanner");
        try {
            SensitiveScanBsBuilder.buildFailClosed(broken);
            Assert.fail("坏类名配置必须构建失败");
        } catch (IllegalArgumentException expected) {
            // 预期行为，下面验证上下文重载时不会污染共享实例。
        }

        SensitiveScanBsContext.reload(broken);
        CharsScanBs after = SensitiveScanBsContext.getCharsScanBs();

        Assert.assertSame("畸形重载不能替换共享扫描器", before, after);
        String afterResult =
                SensitiveScanBsContext.scanAndReplace("value:" + SECRET);
        Assert.assertEquals("重载失败后脱敏能力必须保持",
                beforeResult, afterResult);
    }

    /**
     * 始终抛异常的扫描器，标识与内置手机号不同，追加到扫描列表。
     */
    public static class ThrowingScan implements ICharsScan {

        private final List<CharsScanMatchItem> matchItems =
                new ArrayList<CharsScanMatchItem>();

        @Override
        public void scan(int index, char currentChar, char[] chars,
                         CharsScanContext context) {
            throw new IllegalStateException("boom from custom scanner");
        }

        @Override
        public List<CharsScanMatchItem> getMatchList() {
            return matchItems;
        }

        @Override
        public String getScanType() {
            return "throwing-scan";
        }

        @Override
        public int getPriority() {
            return 0;
        }

        @Override
        public void clear() {
            matchItems.clear();
        }
    }

    /**
     * 始终抛异常的替换策略，覆盖内置手机号替换标识 1。
     */
    public static class ThrowingReplace implements ICharsReplace {

        @Override
        public void replace(StringBuilder stringBuilder, char[] chars,
                            CharsScanMatchItem matchItem,
                            CharsScanContext context) {
            throw new IllegalStateException("boom from custom replace");
        }

        @Override
        public String getScanType() {
            return "1";
        }
    }

}
