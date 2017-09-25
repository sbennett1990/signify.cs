using NUnit.Framework;

namespace SignifyCS.Test {
	public class BaseCryptoFileTests {
		/* TODO:
		 * - test null comment
		 * - test a comment that exceeds comment length
		 * - test a comment with bad header
		 */

		[Test]
		public void CheckComment_GoodInput_ReturnsExpected() {
			const string test_comment = "test comment";

			string res = BaseCryptoFile.CheckComment(makeCommentLine(test_comment));

			Assert.That(res, Is.EqualTo(test_comment));
		}

		[Test]
		public void CheckComment_EmptyComment_ReturnsEmpty() {
			string empty_comment = string.Empty;

			string res = BaseCryptoFile.CheckComment(makeCommentLine(empty_comment));

			Assert.That(res, Is.EqualTo(string.Empty));
		}

		private static string getTestComment() {
			return makeCommentLine("test comment");
		}

		private static string makeCommentLine(string comment) {
			return CommentHeader + comment;
		}

		private static string CommentHeader {
			get {
				return BaseCryptoFile.COMMENT_HEADER;
			}
		}
	}
}
