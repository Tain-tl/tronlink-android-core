package org.tron.metrics.bean;


import androidx.room.ColumnInfo;
import androidx.room.Entity;
import androidx.room.PrimaryKey;

import lombok.Data;

@Data
@Entity(tableName = "uid_mapping")
public class UIdMappingEntity {
    @PrimaryKey(autoGenerate = true)
    private Long id;
    // accepted: [Q-13] Uniqueness needs duplicate reconciliation and atomic migration; the repository lock covers normal app access.
    @ColumnInfo(name = "address")
    private String address;
    @ColumnInfo(name = "uid")
    private String uId;
}
