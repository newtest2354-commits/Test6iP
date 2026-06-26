package com.arista.client.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.arista.client.data.models.Config
import com.arista.client.data.repository.ConfigRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class ConfigViewModel @Inject constructor(
    private val repository: ConfigRepository
) : ViewModel() {

    private val _configs = MutableStateFlow<List<Config>>(emptyList())
    val configs: StateFlow<List<Config>> = _configs

    private val _isLoading = MutableStateFlow(false)
    val isLoading: StateFlow<Boolean> = _isLoading

    fun loadConfigs() {
        viewModelScope.launch {
            repository.getSavedConfigs().collect { configs ->
                _configs.value = configs
            }
        }
    }

    fun fetchConfigs() {
        viewModelScope.launch {
            _isLoading.value = true
            repository.fetchConfigs()
            _isLoading.value = false
        }
    }

    fun connectConfig(config: Config) {
        viewModelScope.launch {
            val updated = config.copy(isActive = true)
            repository.updateConfig(updated)
            loadConfigs()
        }
    }

    fun disconnectConfig(config: Config) {
        viewModelScope.launch {
            val updated = config.copy(isActive = false)
            repository.updateConfig(updated)
            loadConfigs()
        }
    }
}
