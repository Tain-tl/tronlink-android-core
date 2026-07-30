package org.tron.metrics.dao;

import androidx.room.Dao;
import androidx.room.Delete;
import androidx.room.Insert;
import androidx.room.OnConflictStrategy;
import androidx.room.Query;
import androidx.room.Transaction;
import androidx.room.Upsert;

import org.tron.metrics.bean.BalanceCacheEntity;

import java.util.List;

@Dao
public interface BalanceCacheDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    long insert(BalanceCacheEntity balanceCacheEntity);
    
    @Upsert
    void insertAll(List<BalanceCacheEntity> balanceCacheEntities);

    @Delete
    void delete(List<BalanceCacheEntity> balanceCacheEntities);

    @Query("SELECT * FROM balance_cache")
    List<BalanceCacheEntity> getAll();

    @Query("SELECT * FROM balance_cache WHERE updated = 1")
    List<BalanceCacheEntity> getUpdatedBalanceCaches();

    @Query("SELECT * FROM balance_cache WHERE uid = :uid and day = :day")
    BalanceCacheEntity getBalanceCachesByDay(String uid, String day);

    @Query("UPDATE balance_cache SET updated = 0 WHERE id = :id "
            + "AND ((trx_balance IS NULL AND :trxBalance IS NULL) OR trx_balance = :trxBalance) "
            + "AND ((usdt_balance IS NULL AND :usdtBalance IS NULL) OR usdt_balance = :usdtBalance) "
            + "AND ((usd_balance IS NULL AND :usdBalance IS NULL) OR usd_balance = :usdBalance)")
    void clearUpdatedIfUnchanged(
            long id, String trxBalance, String usdtBalance, String usdBalance);

    @Query("DELETE FROM balance_cache WHERE day != :dayNow AND updated = 0")
    void deleteStaleUploaded(String dayNow);

    /**
     * Confirms a successful upload of the given snapshot. Unlike the
     * transaction cache (cumulative counters), balances are point-in-time
     * values: the flag is cleared in place and only where the stored balances
     * still equal the uploaded ones, so a balance change during the network
     * round-trip keeps updated=1 and is re-uploaded next time.
     */
    @Transaction
    default void confirmUploaded(List<BalanceCacheEntity> uploaded, String dayNow) {
        for (BalanceCacheEntity snapshot : uploaded) {
            if (snapshot.getId() == null) {
                continue;
            }
            clearUpdatedIfUnchanged(
                    snapshot.getId(),
                    snapshot.getTrxBalance(),
                    snapshot.getUsdtBalance(),
                    snapshot.getUsdBalance());
        }
        deleteStaleUploaded(dayNow);
    }
}
