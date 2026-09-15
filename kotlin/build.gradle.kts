// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
plugins {
    kotlin("jvm") version "2.2.20"
    kotlin("plugin.serialization") version "2.2.20"
    application
    `java-library`
}

group = "foundation.zoobc"
version = "0.1.0"

repositories { mavenCentral() }

dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.9.0")
    testImplementation(kotlin("test"))
}

// Bytecode for JVM 17 (Android and older servers), built with whatever JDK 17+ is installed.
java { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
kotlin { compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) } }

application { mainClass.set("foundation.zoobc.zbc.cli.MainKt"); applicationName = "zbc-cli" }

// The transaction descriptions of ../spec/transactions ride in the jar as resources, so the
// command table is the spec itself, not a copy kept by hand.
val specTransactions = layout.buildDirectory.dir("generated-resources")
val copySpec by tasks.registering(Copy::class) {
    from("../spec/transactions") { include("*.json") }
    into(specTransactions.map { it.dir("zbc/transactions") })
}
sourceSets.main { resources.srcDir(specTransactions) }
tasks.processResources { dependsOn(copySpec) }

tasks.test {
    useJUnitPlatform()
    systemProperty("zbc.vectors", file("../spec/vectors").absolutePath)
}

tasks.jar { manifest { attributes("Main-Class" to "foundation.zoobc.zbc.cli.MainKt") } }
