use consensus_encode::{Error, Decodable, Encodable, MAX_VEC_SIZE, VarInt};
use std::{io, mem};

pub struct LengthVec<T>(pub Vec<T>);

impl<T: Decodable> Decodable for LengthVec<T> {
    #[inline]
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let len = VarInt::consensus_decode(&mut d)?.0;
        let byte_size = (len as usize)
                            .checked_mul(mem::size_of::<T>())
                            .ok_or(Error::ParseFailed("Invalid length"))?;
        if byte_size > MAX_VEC_SIZE {
            return Err(Error::OversizedVectorAllocation { requested: byte_size, max: MAX_VEC_SIZE })
        }
        let mut ret = Vec::with_capacity(len as usize);
        for _ in 0..len {
            ret.push(Decodable::consensus_decode(&mut d)?);
        }
        Ok(LengthVec(ret))
    }
}

pub struct LengthVecRef<'a, T>(pub &'a Vec<T>);

impl<'a, T: Encodable> Encodable for LengthVecRef<'a, T> {
    #[inline]
    fn consensus_encode<S: io::Write>(
        &self,
        mut s: S,
    ) -> Result<usize, io::Error> {
        let mut len = 0;
        len += VarInt(self.0.len() as u64).consensus_encode(&mut s)?;
        for c in self.0.iter() {
            len += c.consensus_encode(&mut s)?;
        }
        Ok(len)
    }
}
