package com.yourvpndead

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.lifecycle.viewmodel.compose.viewModel
import com.yourvpndead.ui.screens.AboutPage
import com.yourvpndead.ui.screens.MainScreen
import com.yourvpndead.ui.theme.YourVPNDeadTheme
import com.yourvpndead.viewmodel.ScanViewModel

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        setContent {
            YourVPNDeadTheme {
                val viewModel: ScanViewModel = viewModel()
                var selectedTab by remember { mutableIntStateOf(0) }

                Scaffold(
                    bottomBar = {
                        NavigationBar {
                            NavigationBarItem(
                                selected = selectedTab == 0,
                                onClick = { selectedTab = 0 },
                                icon = { Icon(Icons.Default.Security, contentDescription = null) },
                                label = { Text("Сканер") }
                            )
                            NavigationBarItem(
                                selected = selectedTab == 1,
                                onClick = { selectedTab = 1 },
                                icon = { Icon(Icons.Default.Info, contentDescription = null) },
                                label = { Text("Zapret KVN") }
                            )
                        }
                    }
                ) { padding ->
                    Box(Modifier.padding(padding)) {
                        when (selectedTab) {
                            0 -> MainScreen(viewModel)
                            1 -> AboutPage()
                        }
                    }
                }
            }
        }
    }
}
