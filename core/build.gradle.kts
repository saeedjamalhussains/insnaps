plugins {
    kotlin("multiplatform")
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

    sourceSets {
        commonTest.dependencies {
            implementation(kotlin("test"))
        }
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
