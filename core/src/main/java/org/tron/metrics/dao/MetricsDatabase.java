package org.tron.metrics.dao;

import android.content.Context;

import androidx.room.Database;
import androidx.room.Room;
import androidx.room.RoomDatabase;

import org.tron.metrics.bean.BalanceCacheEntity;
import org.tron.metrics.bean.TransactionCacheEntity;
import org.tron.metrics.bean.UIdMappingEntity;

@Database(
        entities = {
                BalanceCacheEntity.class,
                TransactionCacheEntity.class,
                UIdMappingEntity.class
        },
        version = 1,
        exportSchema = false
)
public abstract class MetricsDatabase extends RoomDatabase {

    private static final String DB_NAME = "metrics.db";
    private static volatile MetricsDatabase INSTANCE;

    public static MetricsDatabase getInstance() {
        if (INSTANCE == null) {
            throw new IllegalStateException(
                    "MetricsDatabase not initialized. Call MetricsDatabase.init(context, env) before use.");
        }
        return INSTANCE;
    }

    public static synchronized void init(Context context, String evn) {
        if (INSTANCE == null) {
            synchronized (MetricsDatabase.class) {
                if (INSTANCE == null) {
                    INSTANCE = Room.databaseBuilder(
                                    context.getApplicationContext(),
                                    MetricsDatabase.class,
                                    evn == null || evn.isEmpty() ? DB_NAME : evn + "_" + DB_NAME
                            )
                            .fallbackToDestructiveMigrationOnDowngrade(true)
                            .build();
                }
            }
        }
    }

    public abstract BalanceCacheDao balanceCacheDao();

    public abstract TransactionCacheDao transactionCacheDao();

    public abstract UIDMappingDao uidMappingDao();
}
