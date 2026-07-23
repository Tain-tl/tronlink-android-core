package org.tron.common.utils;

import org.junit.Assert;
import org.junit.Test;

public class RomUtilsTest {

    @Test
    public void parseTotalMemoryGb_validMemInfoLine_returnsTruncatedGb() {
        Assert.assertEquals(4, RomUtils.parseTotalMemoryGb("MemTotal: 4194304 kB"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void parseTotalMemoryGb_nullLine_throwsClearException() {
        RomUtils.parseTotalMemoryGb(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void parseTotalMemoryGb_missingValue_throwsClearException() {
        RomUtils.parseTotalMemoryGb("MemTotal:");
    }
}
