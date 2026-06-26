package com.arista.client.data.repository

import com.arista.client.data.database.ConfigDao
import com.arista.client.data.models.Config
import com.arista.client.network.ApiService
import com.arista.client.utils.ConfigParser
import kotlinx.coroutines.flow.Flow
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class ConfigRepository @Inject constructor(
    private val apiService: ApiService,
    private val configDao: ConfigDao
) {

    suspend fun fetchConfigs(): Result<List<Config>> {
        return try {
            val response = apiService.getConfigs()
            if (response.isSuccessful) {
                val content = response.body() ?: return Result.failure(Exception("Empty response"))
                val configs = parseConfigs(content)
                saveConfigs(configs)
                Result.success(configs)
            } else {
                Result.failure(Exception("Failed to fetch: ${response.code()}"))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    private fun parseConfigs(content: String): List<Config> {
        val configs = mutableListOf<Config>()
        val lines = content.lines()
        
        for (line in lines) {
            val trimmed = line.trim()
            if (trimmed.isEmpty() || trimmed.startsWith("#")) continue
            
            val config = ConfigParser.parseConfigLink(trimmed)
            if (config != null) {
                configs.add(config)
            }
        }
        
        return configs
    }

    suspend fun saveConfigs(configs: List<Config>) {
        configDao.insertAll(configs)
    }

    fun getSavedConfigs(): Flow<List<Config>> {
        return configDao.getAllConfigs()
    }

    suspend fun updateConfig(config: Config) {
        configDao.update(config)
    }
}
