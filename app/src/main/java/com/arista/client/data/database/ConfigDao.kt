package com.arista.client.data.database

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update
import com.arista.client.data.models.Config
import kotlinx.coroutines.flow.Flow

@Dao
interface ConfigDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertAll(configs: List<Config>)

    @Query("SELECT * FROM configs ORDER BY ping ASC")
    fun getAllConfigs(): Flow<List<Config>>

    @Query("SELECT * FROM configs WHERE ping > 0 ORDER BY ping ASC LIMIT :limit")
    fun getBestConfigs(limit: Int): Flow<List<Config>>

    @Update
    suspend fun update(config: Config)

    @Query("DELETE FROM configs")
    suspend fun deleteAll()
}
