plugins {
    kotlin("jvm") version "2.0.20"
    application
}

group = "com.nexsan"
version = "1.0.0"

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.jetbrains.kotlin:kotlin-stdlib")
    
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.0")
    testImplementation("org.junit.jupiter:junit-jupiter-params:5.10.0")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.test {
    useJUnitPlatform()
}

kotlin {
    jvmToolchain(17)
}