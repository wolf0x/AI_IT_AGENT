//! Structured error type inspired by ADK-RUST's AdkError.
//!
//! Provides component-tagged, categorized errors with retry guidance.

use std::fmt;

/// Where the error originated (which subsystem).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorComponent {
    Agent,
    Model,
    Tool,
    Session,
    Config,
    Server,
    Mcp,
    Skill,
    Internal,
}

impl fmt::Display for ErrorComponent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Agent => write!(f, "agent"),
            Self::Model => write!(f, "model"),
            Self::Tool => write!(f, "tool"),
            Self::Session => write!(f, "session"),
            Self::Config => write!(f, "config"),
            Self::Server => write!(f, "server"),
            Self::Mcp => write!(f, "mcp"),
            Self::Skill => write!(f, "skill"),
            Self::Internal => write!(f, "internal"),
        }
    }
}

/// What kind of failure occurred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCategory {
    InvalidInput,
    Unauthorized,
    NotFound,
    RateLimited,
    Timeout,
    Unavailable,
    Cancelled,
    Internal,
    Unsupported,
}

impl ErrorCategory {
    /// Whether this error category suggests a retry.
    pub fn should_retry(&self) -> bool {
        matches!(self, Self::RateLimited | Self::Timeout | Self::Unavailable)
    }
}

impl fmt::Display for ErrorCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput => write!(f, "invalid_input"),
            Self::Unauthorized => write!(f, "unauthorized"),
            Self::NotFound => write!(f, "not_found"),
            Self::RateLimited => write!(f, "rate_limited"),
            Self::Timeout => write!(f, "timeout"),
            Self::Unavailable => write!(f, "unavailable"),
            Self::Cancelled => write!(f, "cancelled"),
            Self::Internal => write!(f, "internal"),
            Self::Unsupported => write!(f, "unsupported"),
        }
    }
}

/// Retry guidance attached to an error.
#[derive(Debug, Clone)]
pub struct RetryHint {
    pub should_retry: bool,
    pub retry_after_ms: Option<u64>,
    pub max_attempts: Option<u32>,
}

impl RetryHint {
    pub fn none() -> Self {
        Self {
            should_retry: false,
            retry_after_ms: None,
            max_attempts: None,
        }
    }

    pub fn retry(after_ms: u64) -> Self {
        Self {
            should_retry: true,
            retry_after_ms: Some(after_ms),
            max_attempts: None,
        }
    }
}

/// The unified error type for RustAgent, modeled after ADK-RUST's AdkError.
#[derive(Debug, Clone)]
pub struct AgentError {
    pub component: ErrorComponent,
    pub category: ErrorCategory,
    pub code: &'static str,
    pub message: String,
    pub retry: RetryHint,
}

impl AgentError {
    pub fn new(component: ErrorComponent, category: ErrorCategory, code: &'static str, message: impl Into<String>) -> Self {
        let cat = category;
        Self {
            component,
            category,
            code,
            message: message.into(),
            retry: if cat.should_retry() { RetryHint::retry(1000) } else { RetryHint::none() },
        }
    }

    // --- Convenience constructors (ADK-RUST pattern) ---

    pub fn agent(message: impl Into<String>) -> Self {
        Self::new(ErrorComponent::Agent, ErrorCategory::Internal, "agent.internal", message)
    }

    pub fn model(message: impl Into<String>) -> Self {
        Self::new(ErrorComponent::Model, ErrorCategory::Internal, "model.internal", message)
    }

    pub fn tool(tool_name: &str, message: impl Into<String>) -> Self {
        Self::new(ErrorComponent::Tool, ErrorCategory::Internal, "tool.error", format!("[{}] {}", tool_name, message.into()))
    }

    pub fn session(message: impl Into<String>) -> Self {
        Self::new(ErrorComponent::Session, ErrorCategory::Internal, "session.internal", message)
    }

    pub fn config(message: impl Into<String>) -> Self {
        Self::new(ErrorComponent::Config, ErrorCategory::InvalidInput, "config.invalid", message)
    }

    pub fn server(message: impl Into<String>) -> Self {
        Self::new(ErrorComponent::Server, ErrorCategory::Internal, "server.internal", message)
    }

    pub fn mcp(server_name: &str, message: impl Into<String>) -> Self {
        Self::new(ErrorComponent::Mcp, ErrorCategory::Internal, "mcp.error", format!("[{}] {}", server_name, message.into()))
    }

    pub fn skill(message: impl Into<String>) -> Self {
        Self::new(ErrorComponent::Skill, ErrorCategory::Internal, "skill.error", message)
    }

    pub fn timeout(component: ErrorComponent, message: impl Into<String>) -> Self {
        Self::new(component, ErrorCategory::Timeout, "timeout", message)
    }

    pub fn not_found(component: ErrorComponent, message: impl Into<String>) -> Self {
        Self::new(component, ErrorCategory::NotFound, "not_found", message)
    }

    pub fn with_retry(mut self, hint: RetryHint) -> Self {
        self.retry = hint;
        self
    }
}

impl fmt::Display for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}.{}] {}: {}",
            self.component, self.category, self.code, self.message
        )
    }
}

impl std::error::Error for AgentError {}

/// Convenience Result type alias.
pub type AgentResult<T> = Result<T, AgentError>;

/// Convert a simple String error into an AgentError (for backward compat in tools).
impl From<String> for AgentError {
    fn from(msg: String) -> Self {
        AgentError::agent(msg)
    }
}

impl From<&str> for AgentError {
    fn from(msg: &str) -> Self {
        AgentError::agent(msg.to_string())
    }
}

impl From<std::io::Error> for AgentError {
    fn from(e: std::io::Error) -> Self {
        AgentError::agent(format!("IO error: {}", e))
    }
}

impl From<serde_json::Error> for AgentError {
    fn from(e: serde_json::Error) -> Self {
        AgentError::agent(format!("JSON error: {}", e))
    }
}
