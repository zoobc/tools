// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
plugins {
    kotlin("jvm") version "2.2.20"
    kotlin("plugin.serialization") version "2.2.20"
    application
    `java-library`
    // Maven Central through the Central Portal, with signing: `gradle publishToMavenCentral`
    // (credentials and key from the environment, see docs/PUBLISHING.md); `gradle publishToMavenLocal` needs nothing.
    id("com.vanniktech.maven.publish") version "0.34.0"
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
    from("../spec/transactions") { include("*.json"); into("zbc/transactions") }
    into(specTransactions)
}
sourceSets.main { resources.srcDir(copySpec) }   // the task itself, so every consumer (jar, sourcesJar) depends on it
tasks.processResources { dependsOn(copySpec) }

tasks.test {
    useJUnitPlatform()
    systemProperty("zbc.vectors", file("../spec/vectors").absolutePath)
}

tasks.jar { manifest { attributes("Main-Class" to "foundation.zoobc.zbc.cli.MainKt") } }

mavenPublishing {
    coordinates("foundation.zoobc", "zbc", version.toString())
    configure(com.vanniktech.maven.publish.KotlinJvm(javadocJar = com.vanniktech.maven.publish.JavadocJar.Empty(), sourcesJar = true))
    publishToMavenCentral()
    if (providers.environmentVariable("ORG_GRADLE_PROJECT_signingInMemoryKey").isPresent) signAllPublications()
    pom {
        name.set("zbc")
        description.set("ZooBC keys, addresses, message signing and sealing, transaction signing, the node client and zbc-cli")
        url.set("https://github.com/zoobc/tools")
        licenses { license { name.set("MIT"); url.set("https://opensource.org/licenses/MIT") } }
        developers { developer { id.set("zoobc"); name.set("ZooBC Foundation"); email.set("info@zoobc.foundation") } }
        scm { url.set("https://github.com/zoobc/tools"); connection.set("scm:git:https://github.com/zoobc/tools.git") }
    }
}
