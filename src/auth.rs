use std::borrow::Cow;

use crate::{
    proto::{Decode, Decoded, Encode},
    service::Service,
    Error,
};

pub(crate) enum UserAuthMessageType {
    Request,
    Failure,
    Successs,
    Banner,
    Unknown(u8),
}

impl Encode for UserAuthMessageType {
    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Self::Request => buf.push(50),
            Self::Failure => buf.push(51),
            Self::Successs => buf.push(52),
            Self::Banner => buf.push(53),
            Self::Unknown(value) => buf.push(*value),
        }
    }
}

impl<'a> Decode<'a> for UserAuthMessageType {
    fn decode(bytes: &'a [u8]) -> Result<Decoded<'a, Self>, Error> {
        let Decoded { value, next } = u8::decode(bytes)?;
        Ok(Decoded {
            value: Self::from(value),
            next,
        })
    }
}

impl From<u8> for UserAuthMessageType {
    fn from(value: u8) -> Self {
        match value {
            50 => Self::Request,
            51 => Self::Failure,
            52 => Self::Successs,
            53 => Self::Banner,
            value => Self::Unknown(value),
        }
    }
}

pub struct AuthService<F> {
    inner: Option<Box<dyn Service>>,
    packet_sender: tokio::sync::mpsc::UnboundedSender<Box<dyn Encode + Send + 'static>>,
    service_provider: F,
}

impl<
        F: FnMut(
            &[u8],
            &[u8],
            tokio::sync::mpsc::UnboundedSender<Box<dyn Encode + Send + 'static>>,
        ) -> Option<Box<dyn Service>>,
    > AuthService<F>
{
    pub fn new(
        service_provider: F,
        packet_sender: tokio::sync::mpsc::UnboundedSender<Box<dyn Encode + Send + 'static>>,
    ) -> Self {
        Self {
            inner: None,
            packet_sender,
            service_provider,
        }
    }
}

struct AuthFailureMsg;

impl Encode for AuthFailureMsg {
    fn encode(&self, buf: &mut Vec<u8>) {
        UserAuthMessageType::Failure.encode(buf);
        b"".encode(buf);
        false.encode(buf);
    }
}

struct AuthSuccesMsg;

impl Encode for AuthSuccesMsg {
    fn encode(&self, buf: &mut Vec<u8>) {
        UserAuthMessageType::Successs.encode(buf);
    }
}

impl<
        F: FnMut(
            &[u8],
            &[u8],
            tokio::sync::mpsc::UnboundedSender<Box<dyn Encode + Send + 'static>>,
        ) -> Option<Box<dyn Service>>,
    > Service for AuthService<F>
{
    fn packet_types(&self) -> Cow<'static, [u8]> {
        let our_types = &[50];
        if let Some(ref inner) = self.inner {
            let mut types = inner.packet_types().into_owned();
            types.extend_from_slice(our_types);
            types.into()
        } else {
            our_types.into()
        }
    }

    fn handle_packet(&mut self, packet: crate::proto::Packet<'_>) {
        let Ok(Decoded {
            value: packet_type,
            next,
        }) = UserAuthMessageType::decode(packet.payload)
        else {
            return;
        };

        if let Some(ref mut inner) = self.inner {
            if !matches!(packet_type, UserAuthMessageType::Unknown(_)) {
                // Ignore per section 5.3 in RFC4252
                return;
            }
            inner.handle_packet(packet);
        } else {
            match packet_type {
                UserAuthMessageType::Request => {
                    let Ok(Decoded {
                        value: username,
                        next,
                    }) = <&[u8]>::decode(next)
                    else {
                        return;
                    };
                    let Ok(Decoded {
                        value: service,
                        next,
                    }) = <&[u8]>::decode(next)
                    else {
                        return;
                    };
                    let Ok(Decoded { value: method, .. }) = <&[u8]>::decode(next) else {
                        return;
                    };
                    match method {
                        b"none" => {
                            if let Some(service) = (self.service_provider)(
                                service,
                                username,
                                self.packet_sender.clone(),
                            ) {
                                self.inner = Some(service);
                                let _ = self.packet_sender.send(Box::new(AuthSuccesMsg));
                            } else {
                                let _ = self.packet_sender.send(Box::new(AuthFailureMsg));
                            }
                        }
                        _ => {
                            let _ = self.packet_sender.send(Box::new(AuthFailureMsg));
                        }
                    }
                }
                _ => {
                    // Packet type we dont need to do anything with as server.
                }
            }
        }
    }
}
