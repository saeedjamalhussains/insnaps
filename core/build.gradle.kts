plugins {
    kotlin("multiplatform")
    id("com.android.library")
}

kotlin {
    // Only the JVM target is enabled here: it compiles `commonMain` and runs the
    // full protocol test suite with no device, emulator or platform SDK present.
    // `androidTarget()` and `iosArm64()/iosSimulatorArm64()` compile the *same*
    // commonMain sources and are enabled once the Android SDK and Xcode are
    // installed -- no core code changes are required to add them.
    jvm {
        compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) }
    }

    // The Android target compiles the SAME commonMain sources as the JVM target.
    // Enabling it is the first real test of the claim that the core is
    // platform-independent: if any JVM-only assumption has crept in, it fails here.
    androidTarget {
        compilations.all {
            compileTaskProvider.configure {
                compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) }
            }
        }
    }

    sourceSets {
        commonTest.dependencies {
            implementation(kotlin("test"))
        }
        // JVM and Android share every JCA primitive that Test Lab verified working
        // on device -- AES-GCM, SHA-256, HMAC, HKDF -- through an intermediate
        // source set. Only the X25519 binding differs, because that is the only
        // part Android's provider cannot supply the JDK way.
        //
        // androidMain deliberately does NOT depend on jvmMain: that arrangement is
        // what let a JDK-only provider look available on Android in the first place.
        val jvmCommonMain by creating { dependsOn(commonMain.get()) }
        jvmMain.get().dependsOn(jvmCommonMain)
        androidMain.get().dependsOn(jvmCommonMain)

        androidMain.dependencies {
            // Tink supplies X25519 without going through the JCA's XDH binding,
            // which Android either lacks (API < 33) or refuses to initialise with
            // NamedParameterSpec (API 34). Measured, not assumed -- see
            // docs/TESTING.md.
            implementation("com.google.crypto.tink:tink-android:1.15.0")
        }
    }
}

android {
    namespace = "com.insnaps.core"
    compileSdk = 34
    defaultConfig {
        // 26 deliberately, not 33: the XDH availability question is exactly what
        // the on-device matrix is meant to answer, so the build must not
        // pre-emptively exclude the devices that would expose it.
        minSdk = 26
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

tasks.withType<Test>().configureEach {
    testLogging {
        events("passed", "failed", "skipped")
        showStandardStreams = true
    }
    // The scale suite instantiates 10,000 live mesh nodes in one JVM.
    maxHeapSize = "3g"
}
