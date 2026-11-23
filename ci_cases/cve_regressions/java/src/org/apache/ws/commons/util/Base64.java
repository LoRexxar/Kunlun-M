/*
 * Copyright 1999,2005 The Apache Software Foundation.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.ws.commons.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.StringWriter;
import java.io.Writer;
import java.lang.reflect.UndeclaredThrowableException;

import org.xml.sax.ContentHandler;
import org.xml.sax.SAXException;


/** Performs Base64 encoding and/or decoding. This is an on-the-fly decoder: Unlike,
 * for example, the commons-codec classes, it doesn't depend on byte arrays. In
 * other words, it has an extremely low memory profile. This is well suited even
 * for very large byte streams.
 */
public class Base64 {
	/** An exception of this type is thrown, if the decoded
	 * character stream contains invalid input.
	 */
	public static class DecodingException extends IOException {
		private static final long serialVersionUID = 3257006574836135478L;
		DecodingException(String pMessage) { super(pMessage); }
	}

	/** An exception of this type is thrown by the {@link SAXEncoder},
	 * if writing to the target handler causes a SAX exception.
	 * This class is required, because the {@link IOException}
	 * allows no cause until Java 1.3.
	 */
	public static class SAXIOException extends IOException {
		private static final long serialVersionUID = 3258131345216451895L;
		final SAXException saxException;
		SAXIOException(SAXException e) {
			super();
			saxException = e;
		}
		/** Returns the encapsulated {@link SAXException}.
		 * @return An exception, which was thrown when invoking
		 * {@link ContentHandler#characters(char[], int, int)}.
		 */
		public SAXException getSAXException() { return saxException; }
	}


	/** Default line separator: \n
	 */
	public static final String LINE_SEPARATOR = "\n";

	/** Default size for line wrapping.
	 */
	public static final int LINE_SIZE = 76;

	/**
     * This array is a lookup table that translates 6-bit positive integer
     * index values into their "Base64 Alphabet" equivalents as specified 
     * in Table 1 of RFC 2045.
     */
    private static final char intToBase64[] = {
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
        'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
        'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
    };

    /**
     * This array is a lookup table that translates unicode characters
     * drawn from the "Base64 Alphabet" (as specified in Table 1 of RFC 2045)
     * into their 6-bit positive integer equivalents.  Characters that
     * are not in the Base64 alphabet but fall within the bounds of the
     * array are translated to -1.
     */
    private static final byte base64ToInt[] = {
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, 52, 53, 54,
        55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4,
        5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
        24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28, 29, 30, 31, 32, 33, 34,
        35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51
    };

	/** An encoder is an object, which is able to encode byte array
	 * in blocks of three bytes. Any such block is converted into an
	 * array of four bytes.
	 */
	public static abstract class Encoder {
		private int num, numBytes;
		private final char[] charBuffer;
		private int charOffset;
		private final int wrapSize;
		private final int skipChars;
		private final String sep;
		private int lineChars = 0;
		/** Creates a new instance.
		 * @param pBuffer The encoders buffer. The encoder will
		 * write to the buffer as long as possible. If the
		 * buffer is full or the end of data is signaled, then
		 * the method {@link #writeBuffer(char[], int, int)}
		 * will be invoked.
		 * @param pWrapSize A nonzero value indicates, that a line
		 * wrap should be performed after the given number of
		 * characters. The value must be a multiple of 4. Zero
		 * indicates, that no line wrap should be performed.
		 * @param pSep The eol sequence being used to terminate
		 * a line in case of line wraps. May be null, in which
		 * case the default value {@link Base64#LINE_SEPARATOR}
		 * is being used.
		 */
		protected Encoder(char[] pBuffer, int pWrapSize, String pSep) {
			charBuffer = pBuffer;
			sep = pSep == null ? null : Base64.LINE_SEPARATOR;
			skipChars = pWrapSize == 0 ? 4 : 4 + sep.length();
			wrapSize = skipChars == 4 ? 0 : pWrapSize;
			if (wrapSize < 0  ||  wrapSize %4 > 0) {
				throw new IllegalArgumentException("Illegal argument for wrap size: " + pWrapSize
												   + "(Expected nonnegative multiple of 4)");
			}
			if (pBuffer.length < skipChars) {
				throw new IllegalArgumentException("The buffer must contain at least " + skipChars
												   + " characters, but has " + pBuffer.length);
			}
		}
		/** Called for writing the buffer contents to the target.
		 * @param pChars The buffer being written.
		 * @param pOffset Offset of first character being written.
		 * @param pLen Number of characters being written.
		 * @throws IOException Writing to the destination failed.
		 */
		protected abstract void writeBuffer(char[] pChars, int pOffset, int pLen) throws IOException;

		private void wrap() {
			for (int j = 0;  j < sep.length();  j++) {
				charBuffer[charOffset++] = sep.charAt(j);
			}
			lineChars = 0;
		}

		/** Encodes the given byte array.
		 * @param pBuffer Byte array being encoded.
		 * @param pOffset Offset of first byte being encoded.
		 * @param pLen Number of bytes being encoded.
		 * @throws IOException Invoking the {@link #writeBuffer(char[],int,int)} method
		 * for writing the encoded data failed.
		 */
		public void write(byte[] pBuffer, int pOffset, int pLen) throws IOException {
			for(int i = 0;  i < pLen;  i++) {
				int b = pBuffer[pOffset++];
				if (b < 0) { b += 256; }
				num = (num << 8) + b;
				if (++numBytes == 3) {
					charBuffer[charOffset++] = intToBase64[num >> 18];
					charBuffer[charOffset++] = intToBase64[(num >> 12) & 0x3f];
					charBuffer[charOffset++] = intToBase64[(num >> 6) & 0x3f];
					charBuffer[charOffset++] = intToBase64[num & 0x3f];
					if (wrapSize > 0) {
						lineChars += 4;
						if (lineChars >= wrapSize) {
							wrap();
						}
					}
					num = 0;
					numBytes = 0;
					if (charOffset + skipChars > charBuffer.length) {
						writeBuffer(charBuffer, 0, charOffset);
						charOffset = 0;
					}
				}
			}
		}
		/** Writes any currently buffered data to the destination.
		 * @throws IOException Invoking the {@link #writeBuffer(char[],int,int)}
		 * method for writing the encoded data failed.
		 */
		public void flush() throws IOException {
			if (numBytes > 0) {
				if (numBytes == 1) {
					charBuffer[charOffset++] = intToBase64[num >> 2];
					charBuffer[charOffset++] = intToBase64[(num << 4) & 0x3f];
					charBuffer[charOffset++] = '=';
					charBuffer[charOffset++] = '=';
				} else {
					charBuffer[charOffset++] = intToBase64[num >> 10];
					charBuffer[charOffset++] = intToBase64[(num >> 4) & 0x3f];
					charBuffer[charOffset++] = intToBase64[(num << 2) & 0x3f];
					charBuffer[charOffset++] = '=';
				}
				lineChars += 4;
				num = 0;
				numBytes = 0;
			}
			if (wrapSize > 0  &&  lineChars > 0) {
				wrap();
			}
			if (charOffset > 0) {
				writeBuffer(charBuffer, 0, charOffset);
				charOffset = 0;
			}
		}
	}

	/** An {@link OutputStream}, which is writing to the given
	 * {@link Encoder}.
	 */
	public static class EncoderOutputStream extends OutputStream {
		private final Encoder encoder;
		/** Creates a new instance, which is creating
		 * output using the given {@link Encoder}.
		 * @param pEncoder The base64 encoder being used.
		 */
		public EncoderOutputStream(Encoder pEncoder) {
			encoder = pEncoder;
		}
		private final byte[] oneByte = new byte[1];
		public void write(int b) throws IOException {
			oneByte[0] = (byte) b;
			encoder.write(oneByte, 0, 1);
		}
		public void write(byte[] pBuffer, int pOffset, int pLen) throws IOException {
			encoder.write(pBuffer, pOffset, pLen);
		}
		public void close() throws IOException {
			encoder.flush();
		}
	}

	/** Returns an {@link OutputStream}, that encodes its input in Base64
	 * and writes it to the given {@link Writer}. If the Base64 stream
	 * ends, then the output streams {@link OutputStream#close()} method
	 * must be invoked. Note, that this will <em>not</em> close the
	 * target {@link Writer}!
	 * @param pWriter Target writer.
	 * @return An output stream, encoding its input in Base64 and writing
	 * the output to the writer <code>pWriter</code>.
	 */
	public static OutputStream newEncoder(Writer pWriter) {
		return newEncoder(pWriter, LINE_SIZE, LINE_SEPARATOR);
	}

	/** Returns an {@link OutputStream}, that encodes its input in Base64
	 * and writes it to the given {@link Writer}. If the Base64 stream
	 * ends, then the output streams {@link OutputStream#close()} method
	 * must be invoked. Note, that this will <em>not</em> close the
	 * target {@link Writer}!
	 * @param pWriter Target writer.
	 * @param pLineSize Size of one line in characters, must be a multiple
	 * of four. Zero indicates, that no line wrapping should occur.
	 * @param pSeparator Line separator or null, in which case the default value
	 * {@link #LINE_SEPARATOR} is used.
	 * @return An output stream, encoding its input in Base64 and writing
	 * the output to the writer <code>pWriter</code>.
	 */
	public static OutputStream newEncoder(final Writer pWriter, int pLineSize, String pSeparator) {
		final Encoder encoder = new Encoder(new char[4096], pLineSize, pSeparator){
			protected void writeBuffer(char[] pBuffer, int pOffset, int pLen) throws IOException {
				pWriter.write(pBuffer, pOffset, pLen);
			}
		};
		return new EncoderOutputStream(encoder);
	}

	/** An {@link Encoder}, which is writing to a SAX content handler.
	 * This is typically used for embedding a base64 stream into an
	 * XML document.
	 */
	public static class SAXEncoder extends Encoder {
		private final ContentHandler handler;
		/** Creates a new instance.
		 * @param pBuffer The encoders buffer.
		 * @param pWrapSize A nonzero value indicates, that a line
		 * wrap should be performed after the given number of
		 * characters. The value must be a multiple of 4. Zero
		 * indicates, that no line wrap should be performed.
		 * @param pSep The eol sequence being used to terminate
		 * a line in case of line wraps. May be null, in which
		 * case the default value {@link Base64#LINE_SEPARATOR}
		 * is being used.
		 * @param pHandler The target handler.
		 */
		public SAXEncoder(char[] pBuffer, int pWrapSize, String pSep,
						  ContentHandler pHandler) {
			super(pBuffer, pWrapSize, pSep);
			handler = pHandler;
		}
		/** Writes to the content handler.
		 * @throws SAXIOException Writing to the content handler
		 * caused a SAXException.
		 */
		protected void writeBuffer(char[] pChars, int pOffset, int pLen) throws IOException {
			try {
				handler.characters(pChars, pOffset, pLen);
			} catch (SAXException e) {
				throw new SAXIOException(e);
			}
		}
	}

	/** Converts the given byte array into a base64 encoded character
	 * array.
	 * @param pBuffer The buffer being encoded.
	 * @param pOffset Offset in buffer, where to begin encoding.
	 * @param pLength Number of bytes being encoded.
	 * @return Character array of encoded bytes.
	 */
	public static String encode(byte[] pBuffer, int pOffset, int pLength) {
		return encode(pBuffer, pOffset, pLength, LINE_SIZE, LINE_SEPARATOR);
	}

	/** Converts the given byte array into a base64 encoded character
	 * array.
	 * @param pBuffer The buffer being encoded.
	 * @param pOffset Offset in buffer, where to begin encoding.
	 * @param pLength Number of bytes being encoded.
	 * @param pLineSize Size of one line in characters, must be a multiple
	 * of four. Zero indicates, that no line wrapping should occur.
	 * @param pSeparator Line separator or null, in which case the default value
	 * {@link #LINE_SEPARATOR} is used.
	 * @return Character array of encoded bytes.
	 */
	public static String encode(byte[] pBuffer, int pOffset, int pLength,
								int pLineSize, String pSeparator) {
		StringWriter sw = new StringWriter();
		OutputStream ostream = newEncoder(sw, pLineSize, pSeparator);
		try {
			ostream.write(pBuffer, pOffset, pLength);
			ostream.close();
		} catch (IOException e) {
			throw new UndeclaredThrowableException(e);
		}
		return sw.toString();
	}

	/** Converts the given byte array into a base64 encoded character
	 * array with the line size {@link #LINE_SIZE} and the separator
	 * {@link #LINE_SEPARATOR}.
	 * @param pBuffer The buffer being encoded.
	 * @return Character array of encoded bytes.
	 */
	public static String encode(byte[] pBuffer) {
		return encode(pBuffer, 0, pBuffer.length);
	}

	/** An encoder is an object, which is able to decode char arrays
	 * in blocks of four bytes. Any such block is converted into a
	 * array of three bytes.
	 */
	public static abstract class Decoder {
		private final byte[] byteBuffer;
		private int byteBufferOffset;
		private int num, numBytes;
		private int eofBytes;
		/** Creates a new instance.
		 * @param pBufLen The decoders buffer size. The decoder will
		 * store up to this number of decoded bytes before invoking
		 * {@link #writeBuffer(byte[],int,int)}.
		 */
		protected Decoder(int pBufLen) {
			byteBuffer = new byte[pBufLen];
		}
		/** Called for writing the decoded bytes to the destination.
		 * @param pBuffer The byte array being written.
		 * @param pOffset Offset of the first byte being written.
		 * @param pLen Number of bytes being written.
		 * @throws IOException Writing to the destination failed.
		 */
		protected abstract void writeBuffer(byte[] pBuffer, int pOffset, int pLen) throws IOException;
		/** Converts the Base64 encoded character array.
		 * @param pData The character array being decoded.
		 * @param pOffset Offset of first character being decoded.
		 * @param pLen Number of characters being decoded.
		 * @throws DecodingException Decoding failed.
		 * @throws IOException An invocation of the {@link #writeBuffer(byte[],int,int)}
		 * method failed.
		 */
		public void write(char[] pData, int pOffset, int pLen) throws IOException {
			for (int i = 0;  i < pLen;  i++) {
				char c = pData[pOffset++];
				if (Character.isWhitespace(c)) {
					continue;
				}
				if (c == '=') {
					++eofBytes;
					num = num << 6;
					switch(++numBytes) {
						case 1:
						case 2:
							throw new DecodingException("Unexpected end of stream character (=)");
						case 3:
							// Wait for the next '='
							break;
						case 4:
							byteBuffer[byteBufferOffset++] = (byte) (num >> 16);
							if (eofBytes == 1) {
								byteBuffer[byteBufferOffset++] = (byte) (num >> 8);
							}
							writeBuffer(byteBuffer, 0, byteBufferOffset);
							byteBufferOffset = 0;
							break;
						case 5:
							throw new DecodingException("Trailing garbage detected");
						default:
							throw new IllegalStateException("Invalid value for numBytes");
					}
				} else {
					if (eofBytes > 0) {
						throw new DecodingException("Base64 characters after end of stream character (=) detected.");
					}
					int result;
					if (c >= 0  &&  c < base64ToInt.length) {
						result = base64ToInt[c];
						if (result >= 0) {
							num = (num << 6) + result;
							if (++numBytes == 4) {
								byteBuffer[byteBufferOffset++] = (byte) (num >> 16);
								byteBuffer[byteBufferOffset++] = (byte) ((num >> 8) & 0xff);
								byteBuffer[byteBufferOffset++] = (byte) (num & 0xff);
								if (byteBufferOffset + 3 > byteBuffer.length) {
									writeBuffer(byteBuffer, 0, byteBufferOffset);
									byteBufferOffset = 0;
								}
								num = 0;
								numBytes = 0;
							}
							continue;
						}
				    }
					if (!Character.isWhitespace(c)) {
						throw new DecodingException("Invalid Base64 character: " + (int) c);
					}
				}
			}
		}
		/** Indicates, that no more data is being expected. Writes all currently
		 * buffered data to the destination by invoking {@link #writeBuffer(byte[],int,int)}.
		 * @throws DecodingException Decoding failed (Unexpected end of file).
		 * @throws IOException An invocation of the {@link #writeBuffer(byte[],int,int)} method failed.
		 */
		public void flush() throws IOException {
			if (numBytes != 0  &&  numBytes != 4) {
				throw new DecodingException("Unexpected end of file");
			}
			if (byteBufferOffset > 0) {
				writeBuffer(byteBuffer, 0, byteBufferOffset);
				byteBufferOffset = 0;
			}
		}
	}

	/** Returns a {@link Writer}, that decodes its Base64 encoded
	 * input and writes it to the given {@link OutputStream}.
	 * Note, that the writers {@link Writer#close()} method will
	 * <em>not</em> close the output stream <code>pStream</code>!
	 * @param pStream Target output stream.
	 * @return An output stream, encoding its input in Base64 and writing
	 * the output to the writer <code>pWriter</code>.
	 */
	public static Writer newDecoder(final OutputStream pStream) {
		return new Writer(){
			private final Decoder decoder = new Decoder(1024){
				protected void writeBuffer(byte[] pBytes, int pOffset, int pLen) throws IOException {
					pStream.write(pBytes, pOffset, pLen);
				}
			};
			public void close() throws IOException {
				flush();
			}
			public void flush() throws IOException {
				decoder.flush();
				pStream.flush();
			}
			public void write(char[] cbuf, int off, int len) throws IOException {
				decoder.write(cbuf, off, len);
			}
		};
	}

	/** Converts the given base64 encoded character buffer into a byte array.
	 * @param pBuffer The character buffer being decoded.
	 * @param pOffset Offset of first character being decoded.
	 * @param pLength Number of characters being decoded.
	 * @return Converted byte array
	 * @throws DecodingException The input character stream contained invalid data.
	 */
	public static byte[] decode(char[] pBuffer, int pOffset, int pLength) throws DecodingException {
		final ByteArrayOutputStream baos = new ByteArrayOutputStream();
		Decoder d = new Decoder(1024){
			protected void writeBuffer(byte[] pBuf, int pOff, int pLen) throws IOException {
				baos.write(pBuf, pOff, pLen);
			}
		};
		try {
			d.write(pBuffer, pOffset, pLength);
			d.flush();
		} catch (DecodingException e) {
			throw e;
		} catch (IOException e) {
			throw new UndeclaredThrowableException(e);
		}
		return baos.toByteArray();
	}

	/** Converts the given base64 encoded character buffer into a byte array.
	 * @param pBuffer The character buffer being decoded.
	 * @return Converted byte array
	 * @throws DecodingException The input character stream contained invalid data.
	 */
	public static byte[] decode(char[] pBuffer) throws DecodingException {
		return decode(pBuffer, 0, pBuffer.length);
	}

	/** Converts the given base64 encoded String into a byte array.
	 * @param pBuffer The string being decoded.
	 * @return Converted byte array
	 * @throws DecodingException The input character stream contained invalid data.
	 */
	public static byte[] decode(String pBuffer) throws DecodingException {
		return decode(pBuffer.toCharArray());
	}
}
