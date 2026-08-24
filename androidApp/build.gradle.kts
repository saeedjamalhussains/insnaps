plugins {
    id("com.android.application")
    kotlin("android")
}

/**
 * Minimal Android host for on-device tests.
 *
 * This is NOT the insnaps app. It exists because Firebase Test Lab needs an
 * application APK plus a test APK, and a library module alone cannot supply the
 * first. It has no UI, no Firebase SDK, and ships nothing to users.
 */
android {
    namespace = "com.insnaps.android"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.insnaps.android"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "0.9-dev"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildTypes {
        getByName("debug") { isMinifyEnabled = false }
    }
}

// Target 17 bytecode using the installed JDK 21, rather than requesting a
// toolchain that would have to be downloaded.
kotlin {
    compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) }
}

dependencies {
    implementation(project(":core"))
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
}
