plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.secscan"
    compileSdk = 36
    defaultConfig {
        applicationId = "com.secscan"
        minSdk = 26
        targetSdk = 36
        versionCode = 3
        versionName = "0.3"
    }
    buildTypes {
        debug {
            isMinifyEnabled = true
            isShrinkResources = true
            isDebuggable = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    buildFeatures { compose = true }
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    implementation(platform("androidx.compose:compose-bom:2025.01.00"))
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.work:work-runtime-ktx:2.9.1")
    implementation("com.github.topjohnwu.libsu:core:6.0.0")
}
