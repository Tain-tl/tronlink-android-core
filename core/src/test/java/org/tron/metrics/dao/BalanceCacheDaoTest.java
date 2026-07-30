package org.tron.metrics.dao;

import org.junit.Assert;
import org.junit.Test;
import org.tron.metrics.bean.BalanceCacheEntity;

import java.util.Collections;
import java.util.List;

public class BalanceCacheDaoTest {

    @Test
    public void confirmUploaded_includesUsdBalanceInSnapshotComparison() {
        BalanceCacheEntity snapshot = new BalanceCacheEntity();
        snapshot.setId(7L);
        snapshot.setTrxBalance("1");
        snapshot.setUsdtBalance("2");
        snapshot.setUsdBalance("3");
        FakeBalanceCacheDao dao = new FakeBalanceCacheDao();

        dao.confirmUploaded(Collections.singletonList(snapshot), "2026-07-29");

        Assert.assertEquals(7L, dao.confirmedId);
        Assert.assertEquals("1", dao.confirmedTrxBalance);
        Assert.assertEquals("2", dao.confirmedUsdtBalance);
        Assert.assertEquals("3", dao.confirmedUsdBalance);
        Assert.assertEquals("2026-07-29", dao.deletedBeforeDay);
    }

    private static class FakeBalanceCacheDao implements BalanceCacheDao {
        private long confirmedId;
        private String confirmedTrxBalance;
        private String confirmedUsdtBalance;
        private String confirmedUsdBalance;
        private String deletedBeforeDay;

        @Override
        public long insert(BalanceCacheEntity balanceCacheEntity) {
            return 0;
        }

        @Override
        public void insertAll(List<BalanceCacheEntity> balanceCacheEntities) {
        }

        @Override
        public void delete(List<BalanceCacheEntity> balanceCacheEntities) {
        }

        @Override
        public List<BalanceCacheEntity> getAll() {
            return Collections.emptyList();
        }

        @Override
        public List<BalanceCacheEntity> getUpdatedBalanceCaches() {
            return Collections.emptyList();
        }

        @Override
        public BalanceCacheEntity getBalanceCachesByDay(String uid, String day) {
            return null;
        }

        @Override
        public void clearUpdatedIfUnchanged(
                long id, String trxBalance, String usdtBalance, String usdBalance) {
            confirmedId = id;
            confirmedTrxBalance = trxBalance;
            confirmedUsdtBalance = usdtBalance;
            confirmedUsdBalance = usdBalance;
        }

        @Override
        public void deleteStaleUploaded(String dayNow) {
            deletedBeforeDay = dayNow;
        }
    }
}
