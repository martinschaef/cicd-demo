/**
* OWASP Benchmark Project
*
* This file is part of the Open Web Application Security Project (OWASP)
* Benchmark Project For details, please see
* <a href="https://www.owasp.org/index.php/Benchmark">https://www.owasp.org/index.php/Benchmark</a>.
*
* The OWASP Benchmark is free software: you can redistribute it and/or modify it under the terms
* of the GNU General Public License as published by the Free Software Foundation, version 2.
*
* The OWASP Benchmark is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
* even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details
*
* @author Martin Schaef
* @created 2021
*/

package org.owasp.benchmark.score.parsers;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.json.JSONArray;
import org.json.JSONObject;
import org.owasp.benchmark.score.BenchmarkScore;

public class AWSCodeGuruReader extends Reader {

	public TestResults parse( File f ) throws Exception {
		String content = new String(Files.readAllBytes(Paths.get(f.getPath())));

		JSONArray recommendations = (new JSONObject(content)).getJSONArray("findings");
		int version = 1; // TODO Need a version string

		final TestResults testResults =
            new TestResults( "AWS CodeGuru Reviewer" ,true,TestResults.ToolType.SAST);

		testResults.setTime("TODO"); // NEED THE SCAN TIME

		for (int i = 0; i < recommendations.length(); i++)
		{
			TestCaseResult testCaseResult = parseCodeGuruFinding( recommendations.getJSONObject(i), 1 );
			if ( testCaseResult != null ) {
                testResults.put( testCaseResult );
			}
		}
		
		return testResults;
	}


	private TestCaseResult parseCodeGuruFinding(JSONObject finding, int version) {
	    try {
            TestCaseResult testCaseResult = new TestCaseResult();
            final JSONObject physicalLocation = finding.getJSONArray("locations")
                                                       .getJSONObject(0)
                                                       .getJSONObject("physicalLocation");


            final String filePath = physicalLocation.getJSONObject("artifactLocation")
                                                    .getString("uri");
            int benchmarkNumber = 0;
            final String message =  finding.getJSONObject("message").getString("text");
            if (filePath.contains(BenchmarkScore.TESTCASENAME)) {
                final String fileName = new File(filePath).getName();
                final String benchmarkNumString = fileName.replace(BenchmarkScore.TESTCASENAME, "")
                                                          .substring(0, 5);
                benchmarkNumber = Integer.parseInt(benchmarkNumString);
            } else {
                Pattern p = Pattern.compile("Benchmark\\d{5}");
                Matcher m = p.matcher(message);
                while (m.find()) {
                    final String benchmarkNumString = m.group().replace(BenchmarkScore.TESTCASENAME, "");
                    benchmarkNumber = Integer.parseInt(benchmarkNumString);
                    break;
                }
            }

            if (benchmarkNumber > 0) {
                testCaseResult.setNumber(benchmarkNumber);
                testCaseResult.setCategory("TODO"); // TODO
                testCaseResult.setEvidence(message);
                int cweNumber = hackCWENumber(testCaseResult.getEvidence());
                testCaseResult.setCWE(cweNumber); // TODO: HACK
                System.err.println("Found CWE " + testCaseResult.getCWE() + " in benchmark " + testCaseResult.getNumber() );
                return testCaseResult;
            }
        }  catch (Exception e ) {
            e.printStackTrace();
        }
	    return null;
    }

    private int hackCWENumber(final String evidence) {
	    if (evidence.contains("Potentially untrusted inputs are used to access a file path")) return 22;

        if (evidence.contains("It looks like your code is constructing an OS command using")) return 78;

        if (evidence.contains("Potentially untrusted inputs reach a method on a [`javax.servlet.http.HttpServletResponse")) return 79;
        if (evidence.contains("It looks like you are using the `DefaultHttpHeaders` constructor with validation disabled")) return 79;
        if (evidence.contains("Potentially untrusted inputs are used to create a [`javax.servlet.http.Cookie`]")) return 79;

        if (evidence.contains("We detected an SQL command that might")) return 89;

        if (evidence.contains("We detected an LDAP search that might use unsanitized input in the search string")) return 90;

	    if (evidence.contains("It looks like your code uses a cipher")) return 327;
        if (evidence.contains("This code uses an algorithm to instantiate the `KeyGenerator` that is insecure")) return 327;
        if (evidence.contains("We detected an insecure use of the [`javax.crypto.KeyGenerator")) return 327;
        if (evidence.contains("It looks like your code uses a cipher object with an insecure transformation")) return 327;
        if (evidence.contains("This code uses an algorithm to instantiate the `KeyGenerator` that is insecure")) return 327;
        if (evidence.contains("An instance of [`java.security.KeyPairGenerator`]")) return 327;
        if (evidence.contains("An insecure cryptographic algorithm is used with [`java.security.KeyPairGenerator`]")) return 327;
        if (evidence.contains("An insecure or incompatible key size is used with [`java.security.KeyPairGenerator`](")) return 327;
        if (evidence.contains("An instance of [`java.security.KeyPairGenerator`]")) return 327;
        if (evidence.contains("It looks like a password might be stored in memory using clear text")) return 327;
        if (evidence.contains("We detected an insecure use of the `javax.crypto.SecretKeyFactory`")) return 327;
        if (evidence.contains("The `Signature` uses a weak cryptographic")) return 327;
        if (evidence.contains("A `Signature` was created, but it was not initialized")) return 327;
        if (evidence.contains("The `Signature` was updated with data before it was initialized")) return 327;
        if (evidence.contains("A `Signature` instance was initialized")) return 327;
        if (evidence.contains("This code seems to implement a symmetric key exchange")) return 327;
        if (evidence.contains("We detected the use of weak cryptographic primitives whic")) return 327;
        if (evidence.contains("This Message Authentication Code (MAC) uses a weak algorithm which might lead to cryptographic vulnerabilities")) return 327;
        if (evidence.contains("We have detected that you are using some TLS cipher")) return 327;

	    if (evidence.contains("This hashing algorithm might be insecure")) return 328;

        if (evidence.contains("We detected the use of cookies which are not secure")) return 614;

        if (evidence.contains("We detected an Xpath query that might use unsanitized input")) return 643;

	    if (evidence.contains("Your code grants file permissions to all users of the system")) return 732;
	    if (evidence.contains("We detected an insecure use of the")) return 0;
	    System.err.println("Unknown evidence " + evidence);
	    return 0;
    }


}
