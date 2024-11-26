import unittest
import bltp

class TestPackets(unittest.TestCase):

    # Test fuer die Kodierung von Integer Fields
    def test_encoding(self):
        values = [0x1F, 0x3F, 0x3FFF, 0x3FFFFF, 0x3FFFFFFF]
        
        # fixed-size fields
        sizes = [8, 8, 16, 24, 32]
        i = 0
        for value in values:
            print(f"\nTesting fixed-size encoding/decoding for value: {value} with size: {sizes[i]} bits")
            encoded = bltp.encode_fixed_size(value, sizes[i])
            decoded = bltp.decode_fixed_size(encoded, sizes[i])
            print(f"Decoded value: {decoded}")
            self.assertEqual(value, decoded)
            i += 1

        # Test für die Fehlermeldung bei ungültiger Größe
        print("\nTesting fixed-size encoding with invalid size (should raise ValueError)")
        with self.assertRaises(ValueError):
            bltp.encode_fixed_size(1, 2)  # fehlen die Parameter bei bltp.encode_fixed_size(value, size)

        # variable-length fields
        for value in values:
            print(f"\nTesting variable-length encoding/decoding for value: {value}")
            encoded = bltp.encode_variable_length(value)
            decoded, length = bltp.decode_variable_length(encoded)
            print(f"Decoded value: {decoded}, Length used: {length}")
            self.assertEqual(value, decoded)

            # Prueft, ob richtige Laenge verwendet wurde
            if value <= 0x3F:
                expected_length = 1
            elif value <= 0x3FFF:    
                expected_length = 2
            elif value <= 0x3FFFFF:
                expected_length = 3
            else:
                expected_length = 4

            print(f"Expected length: {expected_length}")
            self.assertEqual(length, expected_length)

if __name__ == '__main__': 
    unittest.main()
