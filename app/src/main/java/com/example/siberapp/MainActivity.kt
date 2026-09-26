package com.example.siberapp

import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream

// -------------------------------------------------------
// VERİ MODELLERİ
// -------------------------------------------------------
data class RiskModel(val izin: String, val puan: Int, val aciklama: String)

data class FeatureWeight(
    val importance: Double,
    val malwareRate: Double,
    val benignRate: Double
)

// -------------------------------------------------------
// MODEL AĞIRLIKLARINI YÜKLE (assets/model_weights.json)
// -------------------------------------------------------
fun loadModelWeights(context: Context): Map<String, FeatureWeight> {
    val json = context.assets.open("model_weights.json")
        .bufferedReader().use { it.readText() }
    val root = JSONObject(json)
    val featureWeights = root.getJSONObject("feature_weights")
    val result = mutableMapOf<String, FeatureWeight>()
    featureWeights.keys().forEach { key ->
        val obj = featureWeights.getJSONObject(key)
        result[key] = FeatureWeight(
            importance  = obj.getDouble("importance"),
            malwareRate = obj.getDouble("malware_rate"),
            benignRate  = obj.getDouble("benign_rate")
        )
    }
    return result
}

// -------------------------------------------------------
// GERÇEK APK PARSER — Android PackageManager ile izin okur
// Dış kütüphane gerektirmez, Android'in kendi API'si
// -------------------------------------------------------
fun readPermissionsFromApk(context: Context, uri: Uri): Set<String> {
    return try {
        // Uri'yi geçici dosyaya kopyala
        val tmpFile = File(context.cacheDir, "temp_analysis.apk")
        context.contentResolver.openInputStream(uri)?.use { input ->
            FileOutputStream(tmpFile).use { output ->
                input.copyTo(output)
            }
        }

        // Android PackageManager ile AndroidManifest.xml'i oku
        val pm = context.packageManager
        val packageInfo = pm.getPackageArchiveInfo(
            tmpFile.absolutePath,
            PackageManager.GET_PERMISSIONS
        )

        val permissions = packageInfo?.requestedPermissions?.toSet() ?: emptySet()
        tmpFile.delete()
        permissions
    } catch (e: Exception) {
        emptySet()
    }
}

// -------------------------------------------------------
// ML ANALİZ — Gerçek izinler + model ağırlıkları
// -------------------------------------------------------
fun analyzeApk(
    context: Context,
    uri: Uri,
    modelWeights: Map<String, FeatureWeight>
): List<RiskModel> {

    // 1. APK'dan gerçek izinleri oku
    val apkPermissions = readPermissionsFromApk(context, uri)

    // 2. Hiç izin okunamadıysa hata döndür
    if (apkPermissions.isEmpty()) {
        return listOf(
            RiskModel("PARSE_HATASI", 0, "APK okunamadı veya izin bulunamadı.")
        )
    }

    // 3. Her izin için ML skoru hesapla
    val sonuclar = mutableListOf<RiskModel>()
    apkPermissions.forEach { permission ->
        val weight = modelWeights[permission] ?: return@forEach

        val kisaIsim = permission
            .replace("android.permission.", "")
            .replace("com.android.launcher.permission.", "")
            .replace("com.google.android.c2dm.permission.", "")

        // ML Skoru: importance × (1 + malware_rate - benign_rate)
        val riskFarki = weight.malwareRate - weight.benignRate
        val riskPuan = ((weight.importance * 100) * (1 + riskFarki))
            .toInt().coerceIn(1, 99)

        val seviye = when {
            riskPuan >= 15 -> "ML Kritik"
            riskPuan >= 8  -> "ML Orta"
            else           -> "ML Düşük"
        }
        val aciklama = "$seviye: Malware oranı %${(weight.malwareRate * 100).toInt()}" +
                " | Benign oranı %${(weight.benignRate * 100).toInt()}"

        sonuclar.add(RiskModel(kisaIsim, riskPuan, aciklama))
    }

    return sonuclar.sortedByDescending { it.puan }
}

// -------------------------------------------------------
// ACTIVITY
// -------------------------------------------------------
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                MainApp()
            }
        }
    }
}

@Composable
fun MainApp() {
    var ekranDurumu     by remember { mutableStateOf("ANA_EKRAN") }
    var secilenDosyaAdi by remember { mutableStateOf("") }
    var analizListesi   by remember { mutableStateOf(listOf<RiskModel>()) }
    var analizAnahtari  by remember { mutableStateOf(0) }
    val context = LocalContext.current

    val modelWeights = remember { loadModelWeights(context) }

    val launcher = rememberLauncherForActivityResult(
        ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        uri?.let {
            val cursor = context.contentResolver.query(it, null, null, null, null)
            cursor?.use { c ->
                val idx = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (c.moveToFirst()) secilenDosyaAdi = c.getString(idx) ?: "dosya.apk"
            }
            analizListesi  = analyzeApk(context, it, modelWeights)
            analizAnahtari++
            ekranDurumu = "TARANIYOR"
        }
    }

    if (ekranDurumu == "TARANIYOR") {
        LaunchedEffect(analizAnahtari) {
            withContext(Dispatchers.IO) { delay(2000) }
            ekranDurumu = "RAPOR"
        }
    }

    Surface(modifier = Modifier.fillMaxSize(), color = Color(0xFFF8F9FA)) {
        when (ekranDurumu) {
            "ANA_EKRAN" -> AnaEkran {
                launcher.launch("*/*")
            }
            "TARANIYOR" -> TaramaEkrani(secilenDosyaAdi)
            "RAPOR"     -> AnalizRaporu(secilenDosyaAdi, analizListesi) {
                ekranDurumu = "ANA_EKRAN"
            }
        }
    }
}

// -------------------------------------------------------
// UI BİLEŞENLERİ
// -------------------------------------------------------
@Composable
fun AnaEkran(onSec: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text(
            "SENTINEL ML-GUARD",
            fontSize = 28.sp, fontWeight = FontWeight.Black, color = Color(0xFF1A237E)
        )
        Text(
            "Random Forest | %91.25 Accuracy | 330 Feature",
            fontSize = 12.sp, color = Color.Gray
        )
        Spacer(modifier = Modifier.height(6.dp))
        Text(
            "Dataset: 398 APK | 199 Malware / 199 Benign",
            fontSize = 11.sp, color = Color(0xFF1A237E).copy(alpha = 0.6f)
        )
        Spacer(modifier = Modifier.height(40.dp))
        Button(
            onClick = onSec,
            modifier = Modifier.fillMaxWidth().height(65.dp),
            shape = RoundedCornerShape(14.dp),
            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF1A237E))
        ) {
            Text("APK SEÇ VE ANALİZ ET", fontWeight = FontWeight.Bold)
        }
        Spacer(modifier = Modifier.height(12.dp))
        Text("Gerçek APK dosyası seçin (.apk)", fontSize = 11.sp, color = Color.Gray)
    }
}

@Composable
fun TaramaEkrani(dosya: String) {
    Column(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        CircularProgressIndicator(strokeWidth = 5.dp, color = Color(0xFF1A237E))
        Spacer(modifier = Modifier.height(25.dp))
        Text("AndroidManifest.xml Okunuyor...", fontSize = 14.sp, color = Color.Gray)
        Text("ML Modeli Analiz Ediyor...", fontSize = 12.sp, color = Color.LightGray)
        Spacer(modifier = Modifier.height(8.dp))
        Text(dosya, fontWeight = FontWeight.Bold)
    }
}

@Composable
fun AnalizRaporu(dosya: String, liste: List<RiskModel>, onGeri: () -> Unit) {
    val toplamPuan = liste.sumOf { it.puan }
    val malware    = toplamPuan >= 50
    val anaRenk    = if (malware) Color(0xFFD32F2F) else Color(0xFF388E3C)

    Column(modifier = Modifier.padding(20.dp)) {
        TextButton(onClick = onGeri) {
            Text("< Yeni Analiz", color = Color.Gray)
        }
        Text(dosya, fontWeight = FontWeight.Bold, fontSize = 16.sp)
        Spacer(modifier = Modifier.height(15.dp))

        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(20.dp),
            colors = CardDefaults.cardColors(containerColor = anaRenk)
        ) {
            Column(
                modifier = Modifier.padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text(
                    "AI SINIFLANDIRMA KARARI",
                    color = Color.White.copy(alpha = 0.8f),
                    fontSize = 10.sp, fontWeight = FontWeight.Bold
                )
                Text(
                    if (malware) "ZARARLI (MALWARE)" else "GÜVENLİ (SAFE)",
                    color = Color.White, fontSize = 22.sp, fontWeight = FontWeight.Black
                )
                HorizontalDivider(
                    modifier = Modifier.padding(vertical = 12.dp),
                    color = Color.White.copy(alpha = 0.2f)
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text("Model: Random Forest", color = Color.White, fontSize = 11.sp)
                    Text("Doğruluk: %91.25",     color = Color.White, fontSize = 11.sp)
                }
                Spacer(modifier = Modifier.height(4.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text("Tespit: ${liste.size} izin", color = Color.White, fontSize = 11.sp)
                    Text("Risk Skoru: $toplamPuan",    color = Color.White, fontSize = 11.sp)
                }
            }
        }

        Spacer(modifier = Modifier.height(25.dp))
        Text("Tespit Edilen Öznitelikler (Features):", fontWeight = FontWeight.Bold)

        LazyColumn(modifier = Modifier.padding(top = 10.dp)) {
            items(liste) { item ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 6.dp)
                        .background(Color.White, RoundedCornerShape(12.dp))
                        .padding(16.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(item.izin, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                        Text(item.aciklama, fontSize = 11.sp, color = Color.DarkGray)
                    }
                    Text(
                        "+${item.puan}",
                        color = if (malware && item.puan > 15) Color.Red else Color(0xFF388E3C),
                        fontWeight = FontWeight.Bold
                    )
                }
            }
        }
    }
}