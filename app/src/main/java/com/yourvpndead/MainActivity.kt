package com.yourvpndead

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.lifecycle.viewmodel.compose.viewModel
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
                MainScreen(viewModel)
            }
        }
    }
}
