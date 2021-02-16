use crate::lib::Vec;
use serde::{Deserialize, Serialize};
use serde_bare::Uint;

#[derive(Serialize, Deserialize)]
pub struct Message {
    pub version: Uint,
    pub onward_route: Route,
    pub return_route: Route,
    pub payload: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct Route(Vec<Address>);

#[derive(Serialize, Deserialize)]
pub struct Address(Uint, Vec<u8>);

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn empty_message() {
        let message = Message {
            version: Uint(1),
            onward_route: Route(vec![]),
            return_route: Route(vec![]),
            payload: vec![],
        };
        let encoded = serde_bare::to_vec::<Message>(&message).unwrap();
        let expected = [1, 0, 0, 0];
        assert_eq!(encoded, expected);
    }

    #[test]
    fn message_with_payload1() {
        let message = Message {
            version: Uint(1),
            onward_route: Route(vec![]),
            return_route: Route(vec![]),
            payload: vec![100],
        };
        let encoded = serde_bare::to_vec::<Message>(&message).unwrap();
        let expected = [1, 0, 0, 1, 100];
        assert_eq!(encoded, expected);
    }

    #[test]
    fn message_with_payload2() {
        let message = Message {
            version: Uint(1),
            onward_route: Route(vec![]),
            return_route: Route(vec![]),
            payload: vec![104, 101, 108, 108, 111],
        };
        let encoded = serde_bare::to_vec::<Message>(&message).unwrap();
        let expected = [1, 0, 0, 5, 104, 101, 108, 108, 111];
        assert_eq!(encoded, expected);
    }

    #[test]
    fn message_with_onward_route1() {
        let message = Message {
            version: Uint(1),
            onward_route: Route(vec![Address(Uint(5), vec![10, 20, 30])]),
            return_route: Route(vec![]),
            payload: vec![100],
        };
        let encoded = serde_bare::to_vec::<Message>(&message).unwrap();
        let expected = [1, 1, 5, 3, 10, 20, 30, 0, 1, 100];
        assert_eq!(encoded, expected);
    }

    #[test]
    fn message_with_onward_route2() {
        let message = Message {
            version: Uint(1),
            onward_route: Route(vec![
                Address(Uint(5), vec![10, 20, 30]),
                Address(Uint(5), vec![10, 20, 30]),
            ]),
            return_route: Route(vec![]),
            payload: vec![100],
        };
        let encoded = serde_bare::to_vec::<Message>(&message).unwrap();
        let expected = [1, 2, 5, 3, 10, 20, 30, 5, 3, 10, 20, 30, 0, 1, 100];
        assert_eq!(encoded, expected);
    }
}
