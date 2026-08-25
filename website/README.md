# Website

This directory is a standalone static landing page for Automate VIT WiFi. It
does not affect the Windows app or installer build.

## Preview locally

Open `index.html` in a browser, or use any simple static-file server rooted at
this directory.

## Deploy with Cloudflare Pages

1. In Cloudflare, open **Workers & Pages** and select **Create application**.
2. Choose **Pages**, then connect the `ryuk7728/automate-vit-wifi` GitHub
   repository.
3. Use `main` as the production branch.
4. Select **None** as the framework preset. Leave the build command blank and
   set the build output directory to `website`.
5. Deploy. Cloudflare will publish a free `*.pages.dev` address and redeploy
   when changes to `main` are pushed.
6. Open the Pages project’s **Metrics** tab and enable **Web Analytics**.

Cloudflare Web Analytics reports privacy-first site visits, referrers, device
types, countries, and performance without any analytics code in `index.html`.
GitHub Releases records the actual installer download count for each release
asset.

## Add the video tutorial

In `index.html`, set `VIDEO_URL` near the bottom of the file to a YouTube embed
URL, for example:

```js
const VIDEO_URL = "https://www.youtube.com/embed/VIDEO_ID";
```

The tutorial placeholder will automatically become a responsive embedded video.
