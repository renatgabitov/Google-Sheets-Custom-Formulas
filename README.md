# How to create custom Google Sheets functions (and integrate any app using APIs)
Welcome to the magical land of Google Sheets, where formulas reign supreme, and data dances at your fingertips!

This function template is your secret spellbook for conjuring custom Google Sheets formulas. You will also learn how to make API requests directly from Google Sheets.

You can find my detailed video walkthrough here. Click it 👇 

[![VideoTutorial](https://i.ytimg.com/vi/WOnkgJx8EOY/maxresdefault.jpg)](https://youtu.be/WOnkgJx8EOY)

## 1. Create an App Script 
![Image_AppScript](https://github.com/renatgabitov/Google-Sheets-Custom-Formulas/blob/main/support_images/Create%20Script.jpeg?raw=true)

## 2. Define the function
```/**
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
```

Don't forget to press the save button. 

## 3. Look up API documentation

Next up, we need to look up developer documentation for the app that we want to integrate with Google Sheets.

Here is an example: https://apolloio.github.io/apollo-api-docs/?shell#people-api


## 4. Find the HTTP Post URL

We will need to make an HTTP request to the app. To do this we will need a link like this:
```https://api.apollo.io/v1/mixed_people/search```

Add that link inside the code template above. 

## 5. Add variables to your HTTP request

Now, we need to send additional information to the API service we are using. 

You will need to send: 
- the API Key - ${api_key}
- the argument coming from a given cell inside Googe Sheets - ${argument}

This information goes inside the link like this:

```https://api.apollo.io/v1/mixed_people/search?api_key=${api_key}&q_organization_domains=${argument}```

Use ? before your first argument. Then use & to add additional arguments. 

Note that parameter names need to match exactly to what's in the documentation: 
![Documentation](https://github.com/renatgabitov/Google-Sheets-Custom-Formulas/blob/main/support_images/API%20Documentation.jpeg?raw=true)



