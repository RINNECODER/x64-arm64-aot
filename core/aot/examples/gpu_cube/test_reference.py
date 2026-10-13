import unittest

from reference import separate_multiply_add


class Reference(unittest.TestCase):
    def test_keeps_constants_and_separates_scalar_arithmetic(self):
        source = 'store float 0x3FEF1A5C00000000, ptr %projection\n  %12 = tail call float @llvm.fmuladd.f32(float %a, float %b, float %c)\n'
        result, count = separate_multiply_add(source)
        self.assertEqual(count, 1)
        self.assertIn('store float 0x3FEF1A5C00000000, ptr %projection', result)
        self.assertIn('fmul float %a, %b', result)
        self.assertIn('%12 = fadd float %reference_separate_multiply_1, %c', result)

    def test_vector_constants_and_splats(self):
        source = '  %v = call <2 x float> @llvm.fmuladd.v2f32(<2 x float> %a, <2 x float> <float 1.0, float 2.0>, <2 x float> splat (float 3.0))'
        result, count = separate_multiply_add(source)
        self.assertEqual(count, 1)
        self.assertIn('fmul <2 x float> %a, <float 1.0, float 2.0>', result)
        self.assertIn('splat (float 3.0)', result)

    def test_unsupported_fusion_and_name_collisions_reject(self):
        inputs = [
            '%x = call double @llvm.fmuladd.f64(double %a, double %b, double %c)',
            '%x = call float @llvm.fma.f32(float %a, float %b, float %c)',
            '%x = call float @llvm.fmuladd.f32(float %a, float %b, float %c)\n%y = fmul contract float %a, %b',
            '%reference_separate_multiply_1 = call float @llvm.fmuladd.f32(float %a, float %b, float %c)',
        ]
        for source in inputs:
            with self.subTest(source=source), self.assertRaises(ValueError):
                separate_multiply_add(source)


if __name__ == '__main__':
    unittest.main()
