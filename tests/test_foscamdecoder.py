# coding=utf-8



class TestPrinthex(object):
    def test_basic(self):
        import sys
        from lowlevel.FoscDecoder import printhex
        from StringIO import StringIO

        saved_stdout = sys.stdout
        try:
            out = StringIO()
            sys.stdout = out
            printhex("Test")
            output_lines = out.getvalue().strip().split("\n")

            assert len(output_lines) == 2
            assert output_lines[0] == 'length: 4'
            assert output_lines[1] == '0000: 54 65 73 74                                      Test'
        finally:
            sys.stdout = saved_stdout

    def test_multiline(self):
        import sys
        from lowlevel.FoscDecoder import printhex
        from StringIO import StringIO

        saved_stdout = sys.stdout
        try:
            out = StringIO()
            sys.stdout = out
            test_string = "This is longer than one line can hold"
            printhex(test_string)
            output_lines = out.getvalue().strip().split("\n")

            assert len(output_lines) == 4
            assert output_lines[0] == 'length: {}'.format(len(test_string))
            assert output_lines[1] == '0000: 54 68 69 73 20 69 73 20 6c 6f 6e 67 65 72 20 74  This is longer t'
            assert output_lines[2] == '0010: 68 61 6e 20 6f 6e 65 20 6c 69 6e 65 20 63 61 6e  han one line can'
            assert output_lines[3] == '0020: 20 68 6f 6c 64                                    hold'
        finally:
            sys.stdout = saved_stdout


    def test_highlight_single_character(self):
        import sys
        from lowlevel.FoscDecoder import printhex
        from StringIO import StringIO

        saved_stdout = sys.stdout
        try:
            out = StringIO()
            sys.stdout = out
            printhex("Test", highlight=[3])
            output_lines = out.getvalue().strip().split("\n")

            assert len(output_lines) == 2
            assert output_lines[0] == 'length: 4'
            assert output_lines[1] == '0000: 54 65 73 \x1b[43m74\x1b[0m                                      Test'
        finally:
            sys.stdout = saved_stdout

    def test_multicharacter_highlight(self):
        import sys
        from lowlevel.FoscDecoder import printhex
        from StringIO import StringIO

        saved_stdout = sys.stdout
        try:
            out = StringIO()
            sys.stdout = out
            test_string = "This is longer than one line can hold"
            printhex(test_string, highlight=range(3,8))
            output_lines = out.getvalue().strip().split("\n")

            assert len(output_lines) == 4
            assert output_lines[0] == 'length: {}'.format(len(test_string))
            assert output_lines[1] == '0000: 54 68 69 \x1b[43m73 20 69 73 20\x1b[0m 6c 6f 6e 67 65 72 20 74  This is longer t'
            assert output_lines[2] == '0010: 68 61 6e 20 6f 6e 65 20 6c 69 6e 65 20 63 61 6e  han one line can'
            assert output_lines[3] == '0020: 20 68 6f 6c 64                                    hold'
        finally:
            sys.stdout = saved_stdout


    def test_multiline_highlight(self):
        import sys
        from lowlevel.FoscDecoder import printhex
        from StringIO import StringIO

        saved_stdout = sys.stdout
        try:
            out = StringIO()
            sys.stdout = out
            test_string = "This is longer than one line can hold"
            printhex(test_string, highlight=range(3,24))
            output_lines = out.getvalue().strip().split("\n")

            assert len(output_lines) == 4
            assert output_lines[0] == 'length: {}'.format(len(test_string))
            assert output_lines[1] == '0000: 54 68 69 \x1b[43m73 20 69 73 20 6c 6f 6e 67 65 72 20 74\x1b[0m  This is longer t'
            assert output_lines[2] == '0010: \x1b[43m68 61 6e 20 6f 6e 65 20\x1b[0m 6c 69 6e 65 20 63 61 6e  han one line can'
            assert output_lines[3] == '0020: 20 68 6f 6c 64                                    hold'
        finally:
            sys.stdout = saved_stdout
