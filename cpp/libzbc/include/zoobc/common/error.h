// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#ifndef ZOOBC_COMMON_ERROR_H
#define ZOOBC_COMMON_ERROR_H

#include <string>

namespace zoobc {

// Error codes
enum class ErrorCode {
    Success = 0,

    // General errors (1-99)
    Unknown              = 1,
    InvalidArgument      = 2,
    NotFound             = 3,
    AlreadyExists        = 4,
    PermissionDenied     = 5,
    OutOfRange           = 6,
    Unimplemented        = 7,
    Internal             = 8,
    Timeout              = 9,

    // Database errors (100-199)
    DatabaseError        = 100,
    DatabaseNotFound     = 101,
    DatabaseReadError    = 102,
    DatabaseWriteError   = 103,
    DatabaseLocked       = 104,
    DatabaseCorrupt      = 105,

    // Network errors (200-299)
    NetworkError         = 200,
    ConnectionFailed     = 201,
    ConnectionLost       = 202,
    NetworkTimeout       = 203,
    InvalidProtocol      = 204,

    // Crypto errors (300-399)
    CryptoError          = 300,
    InvalidSignature     = 301,
    InvalidPublicKey     = 302,
    InvalidPrivateKey    = 303,
    HashMismatch         = 304,

    // Validation errors (400-499)
    ValidationError      = 400,
    InvalidBlock         = 401,
    InvalidTransaction   = 402,
    InvalidReceipt       = 403,
    InvalidTimestamp     = 404,
    InvalidMerkleRoot    = 405,
    InvalidBlocksmith    = 406,
    InsufficientBalance  = 407,
    DuplicateTransaction = 408,
    MempoolFull          = 409,

    // Consensus errors (500-599)
    ConsensusError       = 500,
    InvalidScore         = 501,
    NodeNotRegistered    = 502,
    NodeNotActive        = 503,
    SelectionFailed      = 504
};

// Error category
enum class ErrorCategory {
    System,
    Database,
    Network,
    Crypto,
    Validation,
    Consensus
};

// Error structure
struct Error {
    ErrorCode code;
    std::string message;
    std::string file;
    int line;

    Error()
        : code(ErrorCode::Success), message(""), file(""), line(0) {}

    Error(ErrorCode c, std::string msg)
        : code(c), message(std::move(msg)), file(""), line(0) {}

    Error(ErrorCode c, std::string msg, std::string f, int l)
        : code(c), message(std::move(msg)), file(std::move(f)), line(l) {}

    // Check if error represents success
    bool IsOk() const {
        return code == ErrorCode::Success;
    }

    // Get error category
    ErrorCategory GetCategory() const {
        int code_value = static_cast<int>(code);

        if (code_value >= 100 && code_value < 200)
            return ErrorCategory::Database;
        if (code_value >= 200 && code_value < 300)
            return ErrorCategory::Network;
        if (code_value >= 300 && code_value < 400)
            return ErrorCategory::Crypto;
        if (code_value >= 400 && code_value < 500)
            return ErrorCategory::Validation;
        if (code_value >= 500 && code_value < 600)
            return ErrorCategory::Consensus;

        return ErrorCategory::System;
    }

    // Convert error code to string
    const char* CodeToString() const {
        switch (code) {
            case ErrorCode::Success:
                return "Success";
            case ErrorCode::Unknown:
                return "Unknown";
            case ErrorCode::InvalidArgument:
                return "InvalidArgument";
            case ErrorCode::NotFound:
                return "NotFound";
            case ErrorCode::AlreadyExists:
                return "AlreadyExists";
            case ErrorCode::PermissionDenied:
                return "PermissionDenied";
            case ErrorCode::OutOfRange:
                return "OutOfRange";
            case ErrorCode::Unimplemented:
                return "Unimplemented";
            case ErrorCode::Internal:
                return "Internal";
            case ErrorCode::Timeout:
                return "Timeout";
            case ErrorCode::DatabaseError:
                return "DatabaseError";
            case ErrorCode::DatabaseNotFound:
                return "DatabaseNotFound";
            case ErrorCode::DatabaseReadError:
                return "DatabaseReadError";
            case ErrorCode::DatabaseWriteError:
                return "DatabaseWriteError";
            case ErrorCode::DatabaseLocked:
                return "DatabaseLocked";
            case ErrorCode::DatabaseCorrupt:
                return "DatabaseCorrupt";
            case ErrorCode::NetworkError:
                return "NetworkError";
            case ErrorCode::ConnectionFailed:
                return "ConnectionFailed";
            case ErrorCode::ConnectionLost:
                return "ConnectionLost";
            case ErrorCode::NetworkTimeout:
                return "NetworkTimeout";
            case ErrorCode::InvalidProtocol:
                return "InvalidProtocol";
            case ErrorCode::CryptoError:
                return "CryptoError";
            case ErrorCode::InvalidSignature:
                return "InvalidSignature";
            case ErrorCode::InvalidPublicKey:
                return "InvalidPublicKey";
            case ErrorCode::InvalidPrivateKey:
                return "InvalidPrivateKey";
            case ErrorCode::HashMismatch:
                return "HashMismatch";
            case ErrorCode::ValidationError:
                return "ValidationError";
            case ErrorCode::InvalidBlock:
                return "InvalidBlock";
            case ErrorCode::InvalidTransaction:
                return "InvalidTransaction";
            case ErrorCode::InvalidReceipt:
                return "InvalidReceipt";
            case ErrorCode::InvalidTimestamp:
                return "InvalidTimestamp";
            case ErrorCode::InvalidMerkleRoot:
                return "InvalidMerkleRoot";
            case ErrorCode::InvalidBlocksmith:
                return "InvalidBlocksmith";
            case ErrorCode::InsufficientBalance:
                return "InsufficientBalance";
            case ErrorCode::DuplicateTransaction:
                return "DuplicateTransaction";
            case ErrorCode::MempoolFull:
                return "MempoolFull";
            case ErrorCode::ConsensusError:
                return "ConsensusError";
            case ErrorCode::InvalidScore:
                return "InvalidScore";
            case ErrorCode::NodeNotRegistered:
                return "NodeNotRegistered";
            case ErrorCode::NodeNotActive:
                return "NodeNotActive";
            case ErrorCode::SelectionFailed:
                return "SelectionFailed";
            default:
                return "UnknownError";
        }
    }

    // Convert to string
    std::string ToString() const {
        if (file.empty()) {
            return std::string(CodeToString()) + ": " + message;
        } else {
            return std::string(CodeToString()) + " [" + file + ":" +
                   std::to_string(line) + "]: " + message;
        }
    }

    // Create success error
    static Error Ok() {
        return Error(ErrorCode::Success, "");
    }
};

// Macro for creating errors with file/line info
#define ZOOBC_ERROR(code, message) \
    zoobc::Error(code, message, __FILE__, __LINE__)

}  // namespace zoobc

#endif  // ZOOBC_COMMON_ERROR_H
