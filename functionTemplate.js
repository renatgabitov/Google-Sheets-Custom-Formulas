/**
 * This is a description of the function. 
 * @param {argument} input This is the description of the "argument" variable.
 * @return This is the description of the result that the user should expect to see.
 * @customfunction //include this line so that it shows up as a suggested formula in Google Sheets
*/

function myFunction(argument){

    //Set up your API request
    const api_key = "XXXXX"; //Replace with your API key.
    const request_url = `XXXXX?key=${api_key}&otherStuff=${argument}`;

    //Pull the data using HTTP GET request
    var response = UrlFetchApp.fetch(request_url, {'muteHttpExceptions': true});

    //Process the data
    if (response.getResponseCode() == 200) {
        var data = JSON.parse(response.getContentText());   //Converts a JSON string into a JS object
        return formatData(data); //Sends data to the formula below that will parse the data. 
    } else {
        return "Error fetching data";
    }
}

function formatData(data) {
    var result = [];
    if (data) {
        var emailValidation = [
            data.data.status,
            data.data.result
        ]
        result = result.concat(emailValidation);
    } else {
        result = result.concat(["No person data found"]);
    }

    return [result]; // Return as a 2D array
}
