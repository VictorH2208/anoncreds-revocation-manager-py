// #![allow(unused_doc_comments, missing_docs)]
// use elliptic_curve::Field;
// use elliptic_curve_tools::SumOfProducts;
// use gennaro_dkg::*;
// use rand_core::{RngCore, SeedableRng};
// use std::num::NonZeroUsize;
// use vsss_rs::{
//     curve25519::*,
//     elliptic_curve::{group::GroupEncoding, Group},
//     IdentifierPrimeField, ParticipantIdGeneratorCollection, ParticipantIdGeneratorType,
//     ReadableShareSet, ShareElement,
// };
// use rand_chacha::ChaCha8Rng;

// /// initialize a participant
// fn init_participant<G: GroupHasher + SumOfProducts + GroupEncoding + Default>(
//     parameters: &Parameters<G>,
// ) -> Box<dyn AnyParticipant<G>> {
//     let mut rng = ChaCha8Rng::from_seed([0u8; 32]);
//     let id =  IdentifierPrimeField(G::Scalar::random(&mut rng));
//     let arr = vec![id];
//     let seq =
//         vec![ParticipantIdGeneratorType::<IdentifierPrimeField<G::Scalar>>::list(&arr)];

//     let participant = ParticipantIdGeneratorCollection::from(&seq).iter().next().unwrap();
//     let p = Box::new(SecretParticipant::<G>::new(participant, &parameters).unwrap());
//     p 
// }

// // next round
// fn next_round<G: GroupHasher + SumOfProducts + GroupEncoding + Default>(
//     participant: &mut Box<dyn AnyParticipant<G>>
// ) -> RoundOutputGenerator<G> {
//     participant.run().unwrap()
// }


// // receive
// fn receive_single<G: GroupHasher + GroupEncoding + SumOfProducts + Default>(
//     participant: &mut dyn AnyParticipant<G>,
//     round_generators: &[RoundOutputGenerator<G>],
// ) {
//     for round_generator in round_generators {
//         for ParticipantRoundOutput {
//             dst_ordinal: ordinal,
//             dst_id: id,
//             data,
//             ..
//         } in round_generator.iter()
//         {
//             let res = participant.receive(data.as_slice());
//         }
//     }
// }

