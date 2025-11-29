//! Test for streaming chunk parsing from SSE data
//! This test verifies that the Message struct can properly deserialize
//! streaming chunks where the role field is optional.

use vulnera_llm::domain::{Choice, LlmResponse, Message};

#[test]
fn test_parse_streaming_chunk_without_role() {
    // This simulates a streaming chunk from DeepSeek API where only content is sent
    let json_chunk = r#"{
        "id": "chat-35f498af02d04bab805a5618cd618e37",
        "object": "chat.completion.chunk",
        "created": 1764419768,
        "model": "deepseek-v3.1",
        "choices": [
            {
                "index": 0,
                "delta": {
                    "content": " malicious"
                },
                "logprobs": null,
                "finish_reason": null
            }
        ],
        "usage": {
            "prompt_tokens": 82,
            "total_tokens": 434,
            "completion_tokens": 352
        }
    }"#;

    // This should deserialize successfully now
    let response: LlmResponse = serde_json::from_str(json_chunk)
        .expect("Failed to parse streaming chunk - the fix didn't work!");

    // Verify the structure
    assert_eq!(response.id, "chat-35f498af02d04bab805a5618cd618e37");
    assert_eq!(response.object, "chat.completion.chunk");
    assert_eq!(response.model, "deepseek-v3.1");
    assert_eq!(response.choices.len(), 1);

    let choice = &response.choices[0];
    assert_eq!(choice.index, 0);
    assert!(choice.message.is_none());

    // The delta should have content but no role (since it's optional now)
    let delta = choice.delta.as_ref().expect("Delta should exist");
    assert!(
        delta.role.is_none(),
        "Role should be None for streaming chunks"
    );
    assert_eq!(delta.content, Some(" malicious".to_string()));
}

#[test]
fn test_parse_streaming_chunk_with_role_in_first_delta() {
    // First delta in a stream includes the role
    let json_chunk = r#"{
        "id": "chat-35f498af02d04bab805a5618cd618e37",
        "object": "chat.completion.chunk",
        "created": 1764419768,
        "model": "deepseek-v3.1",
        "choices": [
            {
                "index": 0,
                "delta": {
                    "role": "assistant",
                    "content": "The response starts here"
                },
                "finish_reason": null
            }
        ]
    }"#;

    let response: LlmResponse =
        serde_json::from_str(json_chunk).expect("Failed to parse streaming chunk with role");

    let delta = &response.choices[0]
        .delta
        .as_ref()
        .expect("Delta should exist");
    assert_eq!(
        delta.role,
        Some("assistant".to_string()),
        "Role should be present in first delta"
    );
    assert_eq!(delta.content, Some("The response starts here".to_string()));
}

#[test]
fn test_message_new_creates_message_with_role() {
    let msg = Message::new("user", "Hello, world!");

    assert_eq!(msg.role, Some("user".to_string()));
    assert_eq!(msg.content, Some("Hello, world!".to_string()));
}

#[test]
fn test_parse_full_response_still_works() {
    // Ensure non-streaming responses still work
    let json_response = r#"{
        "id": "test-id",
        "object": "chat.completion",
        "created": 1764419768,
        "model": "test-model",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "This is the complete response"
                },
                "finish_reason": "stop"
            }
        ],
        "usage": {
            "prompt_tokens": 10,
            "completion_tokens": 8,
            "total_tokens": 18
        }
    }"#;

    let response: LlmResponse =
        serde_json::from_str(json_response).expect("Failed to parse non-streaming response");

    assert!(response.choices[0].message.is_some());
    let msg = response.choices[0].message.as_ref().unwrap();
    assert_eq!(msg.role, Some("assistant".to_string()));
    assert_eq!(
        msg.content,
        Some("This is the complete response".to_string())
    );
}
