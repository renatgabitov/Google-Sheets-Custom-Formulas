# How to create custom Google Sheets functions (and integrate any app using APIs)
Welcome to the magical land of Google Sheets, where formulas reign supreme, and data dances at your fingertips!

This function template is your secret spellbook for conjuring custom Google Sheets formulas. You will also learn how to make API requests directly from Google Sheets.

You can find my detailed video walkthrough here. Click it 👇 

[![VideoTutorial](https://i.ytimg.com/vi/WOnkgJx8EOY/maxresdefault.jpg)](https://youtu.be/WOnkgJx8EOY)

## 1. Create an App Script 
![Image_AppScript](https://media.cleanshot.cloud/media/21749/bfibLKH8jpExUEx5s7Yq3noTfVGXD2qsHM4MnNvl.jpeg?Expires=1706275157&Signature=Cj~xmNq95ksonvV4GRKm74pbVcPvNY9qJyOToWX3EZkOExZiMOcuzP~zfys8TvS6pGfTLAAejVFqp9wwaS-yD~Mbqil2ex337cLBbDtaRoEE9C2OWw6wy0tof2jsC0WjEvtEoFwMVL84Y5ZpjKlRmxmAs1ewxbk7il34Naj3wLlbt79vIe8iv9FIun-WEfGT~OdoeMIM-yELZRMcEwtbi1Av9dYYBnUCfZaGVcSVNqGn8ChhpF2dkvIvl4lR07W7QqZ0ra7KG36OyoSi033Htdb4Luox4~dEGWpT9SyDG07CimGTHe4HywzIJ5W73UxbU28i6GtUQfeftFC2thOt5g__&Key-Pair-Id=K269JMAT9ZF4GZ)

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
![Documentation](https://media.cleanshot.cloud/media/21749/YoGmSAYBKKyt6iydUkIiXjr7JJxe0WQEDoM4oQ7j.jpeg?Expires=1706276206&Signature=hP~KdLkizNW2mBxw27NXJWpsEZ1vIe6JZlR2tL-QwF6RJ43DcCV3SIh9GkxGEbn15mZNwfmkaUQGczJc~m0tIcE0Ce0KSuOPaWXKmKfd5HhIF8huXiszJ0ZFuaHcWOnJRjLfWiK2kqBGI9ZYLOC4IIvi6xVbtU6lyBCGvBCKvG5cs~YsIKaM1liGvb23XGLgpuW9HIP-gcNvPQvtpPIWG548xNhFa6dTTF5mwbw0XrhAuQ4~cCT9~0osBA78ho~R4C7IFus-XV7LzJuzHTpCA1qHozYEJjSzApHdrdV83EK0s5cK~RD9OoDPezttLFYBCB8bcgc3NRzJfF5Y673WdQ__&Key-Pair-Id=K269JMAT9ZF4GZ)



